/**
 * Resource action handlers.
 *
 * A handler is the smallest possible surface: one action name, one input
 * schema, one function. The registry enforces that an action is declared before
 * it can be invoked, and the gateway refuses any action the chain does not
 * carry. There is no dynamic dispatch by string beyond the allowlist.
 */

import { MlpError, invalidRequest } from '../../core/src/errors.ts';
import { isJsonObject, type JsonObject } from '../../core/src/json.ts';

export interface InvocationContext {
  readonly rid: string;
  readonly action: string;
  /** Leaf subject key identifier. */
  readonly subject: string;
  readonly requestId: string;
  readonly now: number;
  /** Wall-clock budget already clamped to the effective grant limits. */
  readonly deadlineMs: number;
  readonly signal: AbortSignal;
}

export interface ActionSpec {
  readonly name: string;
  readonly description?: string;
  /** Throw `invalid_request` to reject; return the normalized input. */
  readonly validate: (input: JsonObject) => JsonObject;
  readonly run: (input: JsonObject, context: InvocationContext) => Promise<JsonObject>;
}

export class HandlerRegistry {
  private readonly actions = new Map<string, ActionSpec>();

  register(spec: ActionSpec): this {
    if (this.actions.has(spec.name)) throw new Error(`action ${spec.name} is already registered`);
    this.actions.set(spec.name, spec);
    return this;
  }

  has(action: string): boolean {
    return this.actions.has(action);
  }

  get(action: string): ActionSpec | undefined {
    return this.actions.get(action);
  }

  list(): Array<{ name: string; description?: string }> {
    return [...this.actions.values()].map((spec) => ({
      name: spec.name,
      ...(spec.description === undefined ? {} : { description: spec.description }),
    }));
  }

  /** Validate input without invoking. Runs before quota is reserved (§12.1). */
  validate(action: string, input: unknown): JsonObject {
    const spec = this.actions.get(action);
    if (!spec) throw new MlpError('denied', 'action is not available on this resource', action);
    if (!isJsonObject(input)) throw invalidRequest('input must be an object');
    return spec.validate(input);
  }

  async invoke(action: string, input: JsonObject, context: InvocationContext): Promise<JsonObject> {
    const spec = this.actions.get(action);
    if (!spec) throw new MlpError('denied', 'action is not available on this resource', action);
    const result = await spec.run(input, context);
    if (!isJsonObject(result)) throw new MlpError('unavailable', 'handler returned a non-object result', action);
    return result;
  }
}

// ---------------------------------------------------------------------------
// Baseline handlers for the two kinds Draft 00 specifies (§12.2).
// ---------------------------------------------------------------------------

function rejectUnknownMembers(input: JsonObject, allowed: string[], action: string): void {
  for (const member of Object.keys(input)) {
    if (!allowed.includes(member)) {
      throw invalidRequest(`${action} does not accept ${member}`);
    }
  }
}

export interface InferenceHandlerOptions {
  /** Provider-side ceiling, which must be at most the grant's byte budget. */
  maxTokens?: number;
  maxPromptBytes?: number;
  /**
   * The actual work. The default is a stub that says so: a reference
   * implementation must not pretend to be a model.
   */
  run?: (input: { prompt: string; maxTokens: number }, context: InvocationContext) => Promise<string>;
}

/**
 * `infer` for `kind: inference`.
 *
 * The schema is fixed by §12.2: `{prompt, max_tokens}` in, `{text}` out. A
 * provider may impose a lower maximum and must reject a higher request rather
 * than silently clamp, because clamping hides a caller's mistake and makes
 * receipt hashes disagree with what the caller thought it asked for.
 */
export function inferenceHandler(options: InferenceHandlerOptions = {}): ActionSpec {
  const maxTokens = options.maxTokens ?? 1024;
  const maxPromptBytes = options.maxPromptBytes ?? 32768;
  const run =
    options.run ??
    (async ({ prompt }: { prompt: string }) =>
      `[reference stub: no model is attached to this handler; ${prompt.length} characters received]`);

  return {
    name: 'infer',
    description: 'Invoke the resource inference action (baseline schema).',
    validate(input) {
      rejectUnknownMembers(input, ['prompt', 'max_tokens'], 'infer');
      const prompt = input.prompt;
      if (typeof prompt !== 'string') throw invalidRequest('infer.prompt must be a string');
      if (Buffer.byteLength(prompt, 'utf8') > maxPromptBytes) {
        throw invalidRequest('infer.prompt exceeds the provider limit');
      }
      const requested = input.max_tokens;
      if (typeof requested !== 'number' || !Number.isInteger(requested) || requested <= 0 || !Number.isSafeInteger(requested)) {
        throw invalidRequest('infer.max_tokens must be a positive integer');
      }
      if (requested > maxTokens) {
        throw invalidRequest(`infer.max_tokens exceeds the provider ceiling of ${maxTokens}`);
      }
      return { prompt, max_tokens: requested };
    },
    async run(input, context) {
      const text = await run({ prompt: input.prompt as string, maxTokens: input.max_tokens as number }, context);
      return { text };
    },
  };
}

export interface McpTool {
  name: string;
  description?: string;
  handler: (args: JsonObject, context: InvocationContext) => Promise<JsonObject>;
}

export interface McpHandlerOptions {
  /** Explicit allowlist. Nothing outside this list is reachable, whatever the grant says. */
  tools: McpTool[];
}

/**
 * `tools.list` and `tools.call` for `kind: mcp`.
 *
 * The grant may authorize `tools.call`; it never decides which tools exist. The
 * allowlist is provider configuration, and a name not on it is rejected before
 * any handler runs.
 */
export function mcpHandler(options: McpHandlerOptions): ActionSpec[] {
  const tools = new Map<string, McpTool>();
  for (const tool of options.tools) {
    if (tools.has(tool.name)) throw new Error(`duplicate MCP tool ${tool.name}`);
    tools.set(tool.name, tool);
  }

  const list: ActionSpec = {
    name: 'tools.list',
    description: 'List the tools this resource exposes.',
    validate(input) {
      rejectUnknownMembers(input, [], 'tools.list');
      return {};
    },
    async run() {
      return {
        tools: [...tools.values()].map((tool) => ({
          name: tool.name,
          ...(tool.description === undefined ? {} : { description: tool.description }),
        })),
      };
    },
  };

  const call: ActionSpec = {
    name: 'tools.call',
    description: 'Call one allowlisted tool by name.',
    validate(input) {
      rejectUnknownMembers(input, ['name', 'arguments'], 'tools.call');
      const name = input.name;
      if (typeof name !== 'string' || name.length === 0) throw invalidRequest('tools.call.name must be a string');
      if (!tools.has(name)) throw new MlpError('denied', 'tool is not on the provider allowlist', name);
      const args = input.arguments;
      if (!isJsonObject(args)) throw invalidRequest('tools.call.arguments must be an object');
      return { name, arguments: args };
    },
    async run(input, context) {
      const tool = tools.get(input.name as string)!;
      const result = await tool.handler(input.arguments as JsonObject, context);
      if (!isJsonObject(result)) throw new MlpError('unavailable', 'tool returned a non-object result', tool.name);
      return { content: result };
    },
  };

  return [list, call];
}

/**
 * An `application`-kind handler that simply echoes a structured payload.
 *
 * This is the honest "wire works" resource: it demonstrates descriptors,
 * grants, proofs, quotas, and receipts without pretending to compute anything.
 */
export function echoHandler(): ActionSpec {
  return {
    name: 'echo',
    description: 'Return the input object unchanged (reference diagnostic action).',
    validate(input) {
      return input;
    },
    async run(input) {
      return { echo: input };
    },
  };
}
