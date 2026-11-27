// Documents held in memory, queried with the subset of the MongoDB query language that the records class defines.
// No imports: the records class and the classes of the components that keep records carry byte copies of this file.

export type Id = string;
export type Doc = { _id: Id; [field: string]: unknown };
export type Filter = Record<string, unknown>;
export type Update = { $set?: Record<string, unknown>; $unset?: Record<string, unknown>; $inc?: Record<string, number> };
export type Sort = Record<string, 1 | -1>;
export type FindOptions = { sort?: Sort; skip?: number; limit?: number; projection?: Record<string, 0 | 1> };
export type IndexSpec = { key: Record<string, 1 | -1>; unique?: boolean; sparse?: boolean; expireAfterSeconds?: number };
export type UpdateOptions = { upsert?: boolean };
export type FindOneAndUpdateOptions = { returnDocument?: "before" | "after"; upsert?: boolean; sort?: Sort };
export type UpdateResult = { matchedCount: number; modifiedCount: number; upsertedId: Id | null };
export type ImportResult = { collections: number; records: number };
export type RecordsErrorCode =
  | "duplicate-key" | "invalid-filter" | "invalid-update" | "invalid-document" | "invalid-name" | "not-configured" | "unavailable";

export interface Collection<T extends Doc = Doc> {
  insertOne(doc: Partial<T> | Record<string, unknown>): Promise<{ insertedId: Id }>;
  findOne(filter?: Filter, options?: FindOptions): Promise<T | null>;
  find(filter?: Filter, options?: FindOptions): Promise<T[]>;
  countDocuments(filter?: Filter): Promise<number>;
  updateOne(filter: Filter, update: Update, options?: UpdateOptions): Promise<UpdateResult>;
  updateMany(filter: Filter, update: Update): Promise<{ matchedCount: number; modifiedCount: number }>;
  findOneAndUpdate(filter: Filter, update: Update, options?: FindOneAndUpdateOptions): Promise<T | null>;
  deleteOne(filter: Filter): Promise<{ deletedCount: number }>;
  deleteMany(filter: Filter): Promise<{ deletedCount: number }>;
  createIndexes(indexes: IndexSpec[]): Promise<void>;
  listIndexes(): Promise<IndexSpec[]>;
}

// The store every records component opens: collections by name, and a portable copy of everything.
export interface Records {
  readonly kind: string;
  collection<T extends Doc = Doc>(name: string): Collection<T>;
  exportAll(): Promise<string>;
  importAll(ndjson: string): Promise<ImportResult>;
  close(): Promise<void>;
}

export class RecordsError extends Error {
  readonly code: RecordsErrorCode;
  constructor(code: RecordsErrorCode, message: string) {
    super(message);
    this.name = "RecordsError";
    this.code = code;
  }
}

export function isDuplicateKey(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: unknown }).code === "duplicate-key";
}

const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

export function validName(name: unknown): name is string {
  return typeof name === "string" && NAME.test(name);
}

// 24 lowercase hexadecimal characters: the creation second, then eight random bytes.
export function newId(now: () => Date = () => new Date()): Id {
  const seconds = Math.floor(now().getTime() / 1000) >>> 0;
  const random = new Uint8Array(8);
  crypto.getRandomValues(random);
  return seconds.toString(16).padStart(8, "0") + Array.from(random, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value) || value instanceof Date) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail(code: RecordsErrorCode, message: string): never {
  throw new RecordsError(code, message);
}

// A stored copy: plain objects, arrays, text, finite numbers, booleans, null and valid dates; undefined fields are dropped.
function normalise(value: unknown, where: string): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid-document", `${where}: numbers must be finite`);
    return value;
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) fail("invalid-document", `${where}: invalid date`);
    return new Date(value.getTime());
  }
  if (Array.isArray(value)) return value.map((item, index) => (item === undefined ? null : normalise(item, `${where}.${index}`)));
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (key.startsWith("$") || key.includes(".") || key.includes("\u0000") || key === "" || key === "__proto__") {
        fail("invalid-document", `${where}: field name ${JSON.stringify(key)}`);
      }
      if (item !== undefined) out[key] = normalise(item, where === "" ? key : `${where}.${key}`);
    }
    return out;
  }
  return fail("invalid-document", `${where}: unsupported value of type ${typeof value}`);
}

function copy<T>(value: T): T {
  return structuredClone(value);
}

function keysOf(path: string): string[] {
  const keys = path.split(".");
  if (keys.some((key) => key === "" || key.startsWith("$") || key.includes("\u0000") || key === "__proto__")) fail("invalid-filter", `field path ${JSON.stringify(path)}`);
  return keys;
}

// Every value a dotted path reaches: through arrays of objects, and into an array by a numeric position.
function reach(value: unknown, keys: string[]): unknown[] {
  if (keys.length === 0) return [value];
  const [head, ...rest] = keys;
  if (Array.isArray(value)) {
    if (/^\d+$/.test(head)) {
      const item = value[Number(head)];
      return item === undefined ? [] : reach(item, rest);
    }
    return value.flatMap((item) => (isPlainObject(item) || Array.isArray(item) ? reach(item, keys) : []));
  }
  if (isPlainObject(value) && Object.hasOwn(value, head)) return reach(value[head], rest);
  return [];
}

// A field that holds an array matches a condition on the array itself or on any of its elements.
function candidates(found: unknown[]): unknown[] {
  return found.flatMap((value) => (Array.isArray(value) ? [value, ...value] : [value]));
}

// Equal values, as MongoDB compares them: two objects are equal only with the same fields in the same order.
function same(a: unknown, b: unknown): boolean {
  if (a instanceof Date || b instanceof Date) return a instanceof Date && b instanceof Date && a.getTime() === b.getTime();
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((item, index) => same(item, b[index]));
  }
  if (isPlainObject(a) || isPlainObject(b)) {
    if (!isPlainObject(a) || !isPlainObject(b)) return false;
    const left = Object.keys(a);
    const right = Object.keys(b);
    return left.length === right.length && left.every((key, position) => right[position] === key && same(a[key], b[key]));
  }
  return a === b;
}

function equals(found: unknown[], value: unknown): boolean {
  if (value === null) return found.length === 0 || candidates(found).some((item) => item === null);
  return candidates(found).some((item) => same(item, value));
}

function comparable(a: unknown, b: unknown): boolean {
  return (typeof a === "number" && typeof b === "number") || (typeof a === "string" && typeof b === "string") ||
    (a instanceof Date && b instanceof Date);
}

// Texts in the order of their characters' code points, as MongoDB orders their UTF-8 bytes; JavaScript's own order of
// UTF-16 units differs where a character above U+FFFF meets one from U+E000 to U+FFFF.
function compareText(a: string, b: string): number {
  const length = Math.min(a.length, b.length);
  for (let position = 0; position < length; position++) {
    const x = a.charCodeAt(position);
    const y = b.charCodeAt(position);
    if (x !== y) {
      const rank = (unit: number) => (unit < 0xd800 ? unit : unit < 0xe000 ? unit + 0x2000 : unit - 0x800);
      return rank(x) - rank(y);
    }
  }
  return a.length - b.length;
}

function order(a: unknown, b: unknown): number {
  if (typeof a === "string" && typeof b === "string") return Math.sign(compareText(a, b));
  const x = a instanceof Date ? a.getTime() : (a as number);
  const y = b instanceof Date ? b.getTime() : (b as number);
  return x < y ? -1 : x > y ? 1 : 0;
}

function isOperatorObject(value: unknown): value is Record<string, unknown> {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  const operators = keys.filter((key) => key.startsWith("$")).length;
  if (operators > 0 && operators !== keys.length) fail("invalid-filter", "a condition mixes operators and fields");
  return operators > 0;
}

function operator(found: unknown[], name: string, argument: unknown): boolean {
  if (argument === undefined) fail("invalid-filter", `${name} has no value`);
  switch (name) {
    case "$eq":
      return equals(found, argument);
    case "$ne":
      return !equals(found, argument);
    case "$in":
      if (!Array.isArray(argument)) fail("invalid-filter", "$in needs an array");
      return argument.some((item) => equals(found, item));
    case "$nin":
      if (!Array.isArray(argument)) fail("invalid-filter", "$nin needs an array");
      return !argument.some((item) => equals(found, item));
    case "$exists":
      return (found.length > 0) === Boolean(argument);
    case "$gt":
    case "$gte":
    case "$lt":
    case "$lte":
      return candidates(found).some((item) => {
        if (!comparable(item, argument)) return false;
        const result = order(item, argument);
        return name === "$gt" ? result > 0 : name === "$gte" ? result >= 0 : name === "$lt" ? result < 0 : result <= 0;
      });
    default:
      return fail("invalid-filter", `unsupported operator ${name}`);
  }
}

// Whether a document matches a filter that checkFilter has passed.
function test(doc: Doc, filter: Filter): boolean {
  return Object.entries(filter).every(([key, condition]) => {
    if (key === "$or" || key === "$and") {
      const parts = condition as Filter[];
      return key === "$or" ? parts.some((part) => test(doc, part)) : parts.every((part) => test(doc, part));
    }
    const found = reach(doc, keysOf(key));
    if (isOperatorObject(condition)) return Object.entries(condition).every(([name, argument]) => operator(found, name, argument));
    return equals(found, condition);
  });
}

export function matches(doc: Doc, filter: Filter = {}): boolean {
  return test(doc, checkFilter(filter));
}

function filterValue(value: unknown, where: string): unknown {
  try {
    return normalise(value, where);
  } catch (error) {
    return fail("invalid-filter", (error as Error).message);
  }
}

const COMPARISONS = new Set(["$eq", "$ne", "$gt", "$gte", "$lt", "$lte"]);

// The filter as `matches` reads it, with every rule checked before any document is read, so a filter the subset does
// not allow is refused even on an empty collection. Every value in a filter is one that could be stored.
function checkFilter(filter: unknown): Filter {
  if (!isPlainObject(filter)) fail("invalid-filter", "a filter is an object");
  const out: Filter = {};
  for (const [key, condition] of Object.entries(filter)) {
    if (condition === undefined) fail("invalid-filter", `${key} has no value`);
    if (key === "$or" || key === "$and") {
      if (!Array.isArray(condition) || condition.length === 0) fail("invalid-filter", `${key} needs a non-empty array`);
      out[key] = condition.map(checkFilter);
      continue;
    }
    if (key.startsWith("$")) fail("invalid-filter", `unsupported operator ${key}`);
    keysOf(key);
    if (!isOperatorObject(condition)) {
      out[key] = filterValue(condition, key);
      continue;
    }
    const checked: Record<string, unknown> = {};
    for (const [name, argument] of Object.entries(condition)) {
      if (argument === undefined) fail("invalid-filter", `${name} has no value`);
      if (name === "$in" || name === "$nin") {
        if (!Array.isArray(argument)) fail("invalid-filter", `${name} needs an array`);
        checked[name] = argument.map((item) => filterValue(item, `${key} ${name}`));
      } else if (name === "$exists") {
        checked[name] = argument;
      } else if (COMPARISONS.has(name)) {
        checked[name] = filterValue(argument, `${key} ${name}`);
      } else {
        fail("invalid-filter", `unsupported operator ${name}`);
      }
    }
    out[key] = checked;
  }
  return out;
}

// MongoDB's order of types: missing and null, numbers, text, objects, arrays, booleans, dates.
function rank(value: unknown): number {
  if (value === undefined || value === null) return 0;
  if (typeof value === "number") return 1;
  if (typeof value === "string") return 2;
  if (Array.isArray(value)) return 4;
  if (value instanceof Date) return 6;
  if (typeof value === "boolean") return 5;
  return 3;
}

function compareValues(a: unknown, b: unknown): number {
  const difference = rank(a) - rank(b);
  if (difference !== 0) return difference;
  if (comparable(a, b)) return order(a, b);
  if (typeof a === "boolean") return Number(a) - Number(b);
  return 0;
}

function sorted(docs: Doc[], sort: Sort | undefined): Doc[] {
  if (!sort) return docs;
  const fields = Object.entries(sort).map(([path, direction]) => {
    if (direction !== 1 && direction !== -1) fail("invalid-filter", "sort directions are 1 and -1");
    return [keysOf(path), direction] as const;
  });
  return [...docs].sort((a, b) => {
    for (const [keys, direction] of fields) {
      const result = compareValues(reach(a, keys)[0], reach(b, keys)[0]);
      if (result !== 0) return result * direction;
    }
    return 0;
  });
}

function checkProjection(projection: unknown): Record<string, 0 | 1> | undefined {
  if (projection === undefined || projection === null) return undefined;
  const rule = "projections name top-level fields with 0 or 1";
  if (!isPlainObject(projection)) fail("invalid-filter", rule);
  const entries = Object.entries(projection);
  for (const [key, value] of entries) {
    if ((value !== 0 && value !== 1) || key === "" || key.includes(".") || key.startsWith("$") || key === "__proto__") fail("invalid-filter", rule);
  }
  const fields = entries.filter(([key]) => key !== "_id");
  if (fields.some(([, value]) => value === 1) && fields.some(([, value]) => value === 0)) {
    fail("invalid-filter", "a projection either includes or excludes fields");
  }
  return entries.length ? (projection as Record<string, 0 | 1>) : undefined;
}

// As MongoDB: fields given 1 are included (with _id unless _id is 0), else fields given 0 are left out; { _id: 1 } alone
// includes _id only.
function project(doc: Doc, projection: Record<string, 0 | 1> | undefined): Doc {
  if (!projection) return doc;
  const fields = Object.entries(projection).filter(([key]) => key !== "_id");
  const including = fields.some(([, value]) => value === 1) || (fields.length === 0 && projection._id === 1);
  const out: Record<string, unknown> = {};
  if (including) {
    if (projection._id !== 0) out._id = doc._id;
    for (const [key] of fields) if (Object.hasOwn(doc, key)) out[key] = doc[key];
  } else {
    Object.assign(out, doc);
    for (const [key] of fields) delete out[key];
    if (projection._id === 0) delete out._id;
  }
  return out as Doc;
}

// A position past the end of an array fills the gap with null, as MongoDB does.
function placeAt(array: unknown[], position: number, value: unknown): void {
  while (array.length < position) array.push(null);
  array[position] = value;
}

// A dotted path creates the objects missing on its way; through any other value, null included, it is refused.
function setAt(target: Record<string, unknown>, keys: string[], value: unknown): void {
  let node: unknown = target;
  for (let index = 0; index < keys.length - 1; index++) {
    const key = keys[index];
    const container = node as Record<string, unknown> & unknown[];
    if (Array.isArray(container) && /^\d+$/.test(key)) {
      if (container[Number(key)] === undefined) placeAt(container, Number(key), {});
      node = container[Number(key)];
    } else if (isPlainObject(container)) {
      if (!Object.hasOwn(container, key)) container[key] = {};
      node = container[key];
    } else {
      fail("invalid-update", `cannot set ${keys.join(".")} inside a value that is not an object`);
    }
  }
  const last = keys[keys.length - 1];
  if (Array.isArray(node) && /^\d+$/.test(last)) placeAt(node, Number(last), value);
  else if (isPlainObject(node)) node[last] = value;
  else fail("invalid-update", `cannot set ${keys.join(".")} inside a value that is not an object`);
}

function unsetAt(target: Record<string, unknown>, keys: string[]): void {
  let node: unknown = target;
  for (const key of keys.slice(0, -1)) {
    if (!isPlainObject(node) || !Object.hasOwn(node, key)) return;
    node = node[key];
  }
  if (isPlainObject(node)) delete node[keys[keys.length - 1]];
}

function updateKeys(path: string): string[] {
  try {
    return keysOf(path);
  } catch {
    return fail("invalid-update", `field path ${JSON.stringify(path)}`);
  }
}

function applyUpdate(doc: Doc, update: Update, inserting: boolean): Doc {
  if (!isPlainObject(update)) fail("invalid-update", "an update is an object");
  const names = Object.keys(update);
  if (names.length === 0) fail("invalid-update", "an update needs $set, $unset or $inc");
  const seen: string[] = [];
  for (const name of names) {
    if (name !== "$set" && name !== "$unset" && name !== "$inc") fail("invalid-update", `unsupported update operator ${name}`);
    const fields = (update as Record<string, unknown>)[name];
    if (!isPlainObject(fields)) fail("invalid-update", `${name} takes an object`);
    for (const path of Object.keys(fields)) {
      // A field and a field inside it are one field.
      const other = seen.find((done) => done === path || done.startsWith(`${path}.`) || path.startsWith(`${done}.`));
      if (other !== undefined) fail("invalid-update", other === path ? `${path} is changed twice` : `${other} and ${path} change the same field`);
      seen.push(path);
    }
  }
  const next = copy(doc) as Record<string, unknown>;
  for (const [path, value] of Object.entries(update.$set ?? {})) {
    const keys = updateKeys(path);
    if (path === "_id" && !inserting && !same(value, doc._id)) fail("invalid-update", "_id cannot change");
    if (value === undefined) unsetAt(next, keys);
    else setAt(next, keys, normalise(value, path));
  }
  for (const path of Object.keys(update.$unset ?? {})) {
    if (path === "_id") fail("invalid-update", "_id cannot be removed");
    unsetAt(next, updateKeys(path));
  }
  for (const [path, amount] of Object.entries(update.$inc ?? {})) {
    if (typeof amount !== "number" || !Number.isFinite(amount)) fail("invalid-update", `$inc ${path} takes a number`);
    const keys = updateKeys(path);
    const found = reach(next, keys);
    const current = found.length ? found[0] : 0;
    if (typeof current !== "number") fail("invalid-update", `$inc ${path} on a value that is not a number`);
    setAt(next, keys, current + amount);
  }
  return next as Doc;
}

// The equality fields MongoDB puts in a document an upsert inserts: a value, $eq or a one-value $in, also inside $and or
// a one-clause $or. As in MongoDB, a field given twice (or a field and a field inside it) leaves the document unknown.
function seedFromFilter(filter: Filter, into: Record<string, unknown>, seeded: string[] = []): void {
  const seed = (path: string, value: unknown) => {
    const other = seeded.find((done) => done === path || done.startsWith(`${path}.`) || path.startsWith(`${done}.`));
    if (other !== undefined) fail("invalid-filter", `an upsert cannot take both ${other} and ${path} from its filter`);
    seeded.push(path);
    setAt(into, keysOf(path), normalise(value, path));
  };
  for (const [key, condition] of Object.entries(filter)) {
    if ((key === "$and" || key === "$or") && Array.isArray(condition)) {
      if (key === "$and" || condition.length === 1) for (const part of condition) seedFromFilter(part as Filter, into, seeded);
    } else if (!key.startsWith("$")) {
      if (isOperatorObject(condition)) {
        const values = [...(Object.hasOwn(condition, "$eq") ? [condition.$eq] : []),
          ...(Array.isArray(condition.$in) && condition.$in.length === 1 ? condition.$in : [])];
        for (const value of values) seed(key, value);
      } else {
        seed(key, condition);
      }
    }
  }
}

// A missing field counts as null; a sparse index leaves out a document that has none of its fields.
function indexKey(doc: Doc, index: IndexSpec): unknown[] | null {
  const values: unknown[] = [];
  let present = false;
  for (const path of Object.keys(index.key)) {
    const found = reach(doc, keysOf(path));
    present ||= found.length > 0;
    values.push(found.length === 0 ? null : found[0]);
  }
  return index.sparse && !present ? null : values;
}

// Two keys are one index when they name the same fields, in the same order, with the same directions.
function sameKey(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const left = Object.entries(a);
  const right = Object.entries(b);
  return left.length === right.length && left.every(([field, direction], position) => right[position][0] === field && right[position][1] === direction);
}

// MongoDB keeps whole seconds of expiry, up to the largest 32-bit integer.
const LONGEST_EXPIRY = 2147483647;

function checkIndex(index: unknown): IndexSpec {
  if (!isPlainObject(index) || !isPlainObject(index.key) || Object.keys(index.key).length === 0) fail("invalid-filter", "an index needs a key");
  for (const [path, direction] of Object.entries(index.key)) {
    keysOf(path);
    if (direction !== 1 && direction !== -1) fail("invalid-filter", "index directions are 1 and -1");
  }
  const spec: IndexSpec = { key: { ...(index.key as Record<string, 1 | -1>) } };
  if (index.unique) spec.unique = true;
  if (index.sparse) spec.sparse = true;
  if (index.expireAfterSeconds !== undefined) {
    const seconds = index.expireAfterSeconds;
    if (!Number.isInteger(seconds) || (seconds as number) < 0 || (seconds as number) > LONGEST_EXPIRY || Object.keys(index.key).length !== 1) {
      fail("invalid-filter", `expireAfterSeconds is a whole number of seconds up to ${LONGEST_EXPIRY} on a one-field index`);
    }
    spec.expireAfterSeconds = seconds as number;
  }
  return spec;
}

type Table = { docs: Doc[]; indexes: IndexSpec[] };

export type StoreOptions = { now?: () => Date; onChange?: () => void };

export interface Store {
  collection<T extends Doc = Doc>(name: string): Collection<T>;
  names(): string[];
  exportAll(): string;
  importAll(ndjson: string): ImportResult;
  clear(): void;
  // Not part of the records class: the class's MongoDB driver stand-in drops indexes with it.
  dropIndex(collection: string, key: Record<string, 1 | -1>): boolean;
}

export function encode(value: unknown): unknown {
  if (value instanceof Date) return { $date: value.toISOString() };
  if (Array.isArray(value)) return value.map(encode);
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encode(item)]));
  return value;
}

export function decode(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(decode);
  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === "$date" && typeof value.$date === "string") {
      const date = new Date(value.$date);
      if (Number.isNaN(date.getTime())) fail("invalid-document", `invalid date ${value.$date}`);
      return date;
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decode(item)]));
  }
  return value;
}

// One line per index, then one per document, collection by collection in name order.
export function exportLines(tables: Array<{ name: string; indexes: IndexSpec[]; docs: Doc[] }>): string {
  const lines: string[] = [];
  for (const table of [...tables].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    for (const index of table.indexes) lines.push(JSON.stringify({ collection: table.name, index }));
    for (const doc of table.docs) lines.push(JSON.stringify({ collection: table.name, document: encode(doc) }));
  }
  return lines.length ? lines.join("\n") + "\n" : "";
}

export type ImportLine = { collection: string; index?: IndexSpec; document?: Doc };

export function parseLines(ndjson: string): ImportLine[] {
  if (typeof ndjson !== "string") fail("invalid-document", "an export is text");
  const out: ImportLine[] = [];
  ndjson.split("\n").forEach((line, number) => {
    if (line.trim() === "") return;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      fail("invalid-document", `line ${number + 1} is not JSON`);
    }
    if (!isPlainObject(value) || !validName(value.collection) || (value.index === undefined) === (value.document === undefined)) {
      fail("invalid-document", `line ${number + 1} needs a collection and either an index or a document`);
    }
    if (value.index !== undefined) {
      try {
        out.push({ collection: value.collection, index: checkIndex(value.index) });
      } catch (error) {
        fail("invalid-document", `line ${number + 1}: ${(error as Error).message}`);
      }
    } else {
      const doc = decode(value.document);
      if (!isPlainObject(doc) || typeof doc._id !== "string" || doc._id === "") fail("invalid-document", `line ${number + 1}: a document needs a text _id`);
      out.push({ collection: value.collection, document: doc as Doc });
    }
  });
  return out;
}

export function createStore(options: StoreOptions = {}): Store {
  const now = options.now ?? (() => new Date());
  const changed = options.onChange ?? (() => {});
  const tables = new Map<string, Table>();

  function table(name: string): Table {
    if (!validName(name)) fail("invalid-name", `collection name ${JSON.stringify(name)}`);
    let found = tables.get(name);
    if (!found) {
      found = { docs: [], indexes: [] };
      tables.set(name, found);
    }
    return found;
  }

  // Documents whose time-to-live index date has passed are removed before any read or write.
  function sweep(entry: Table): void {
    const expiring = entry.indexes.filter((index) => index.expireAfterSeconds !== undefined);
    if (!expiring.length) return;
    const instant = now().getTime();
    const before = entry.docs.length;
    entry.docs = entry.docs.filter((doc) => !expiring.some((index) => {
      const value = reach(doc, keysOf(Object.keys(index.key)[0]));
      return candidates(value).some((item) => item instanceof Date && item.getTime() + index.expireAfterSeconds! * 1000 <= instant);
    }));
    if (entry.docs.length !== before) changed();
  }

  function checkUnique(entry: Table, candidate: Doc, replacing: Doc | null): void {
    for (const doc of entry.docs) {
      if (doc === replacing) continue;
      if (doc._id === candidate._id) fail("duplicate-key", `duplicate _id ${candidate._id}`);
      for (const index of entry.indexes) {
        if (!index.unique) continue;
        const a = indexKey(doc, index);
        const b = indexKey(candidate, index);
        if (a && b && a.every((value, position) => same(value, b[position]))) {
          fail("duplicate-key", `duplicate key ${JSON.stringify(Object.keys(index.key))}`);
        }
      }
    }
  }

  function prepare(input: unknown): Doc {
    if (!isPlainObject(input)) fail("invalid-document", "a document is an object");
    const doc = normalise(input, "") as Record<string, unknown>;
    if (doc._id === undefined || doc._id === null) doc._id = newId(now);
    if (typeof doc._id !== "string" || doc._id === "") fail("invalid-document", "_id is text");
    return doc as Doc;
  }

  function insert(entry: Table, input: unknown): Doc {
    const doc = prepare(input);
    checkUnique(entry, doc, null);
    entry.docs.push(doc);
    return doc;
  }

  function select(entry: Table, filter: Filter | undefined, options: FindOptions = {}): Doc[] {
    const where = checkFilter(filter ?? {});
    const skip = options.skip ?? 0;
    if (!Number.isInteger(skip) || skip < 0) fail("invalid-filter", "skip is a whole number");
    if (options.limit !== undefined && (!Number.isInteger(options.limit) || options.limit < 0)) fail("invalid-filter", "limit is a whole number");
    sweep(entry);
    let found = entry.docs.filter((doc) => test(doc, where));
    found = sorted(found, options.sort);
    found = found.slice(skip, options.limit ? skip + options.limit : undefined);
    return found;
  }

  function replace(entry: Table, previous: Doc, next: Doc): boolean {
    checkUnique(entry, next, previous);
    const position = entry.docs.indexOf(previous);
    entry.docs[position] = next;
    return !same(previous, next);
  }

  // The filter's equality fields with the update applied, under the _id the filter or $set gives (they may not differ).
  function upsert(entry: Table, filter: Filter, update: Update): Doc {
    const seed: Record<string, unknown> = {};
    seedFromFilter(filter, seed);
    const given = isPlainObject(update) && isPlainObject(update.$set) ? update.$set._id : undefined;
    if (seed._id !== undefined && given !== undefined && !same(seed._id, given)) fail("invalid-update", "_id cannot change");
    const created = applyUpdate(prepare(seed), update, true);
    return insert(entry, created);
  }

  function collection<T extends Doc = Doc>(name: string): Collection<T> {
    const entry = table(name);
    const api: Collection<Doc> = {
      async insertOne(doc) {
        const stored = insert(entry, doc);
        changed();
        return { insertedId: stored._id };
      },
      async findOne(filter, options) {
        const projection = checkProjection(options?.projection);
        const [doc] = select(entry, filter, { ...options, limit: 1 });
        return doc ? copy(project(doc, projection)) : null;
      },
      async find(filter, options) {
        const projection = checkProjection(options?.projection);
        return select(entry, filter, options).map((doc) => copy(project(doc, projection)));
      },
      async countDocuments(filter) {
        return select(entry, filter).length;
      },
      async updateOne(filter, update, options) {
        const [doc] = select(entry, filter, { limit: 1 });
        if (!doc) {
          if (!options?.upsert) {
            applyUpdate({ _id: "" }, update, true);
            return { matchedCount: 0, modifiedCount: 0, upsertedId: null };
          }
          const created = upsert(entry, filter, update);
          changed();
          return { matchedCount: 0, modifiedCount: 0, upsertedId: created._id };
        }
        const modified = replace(entry, doc, applyUpdate(doc, update, false));
        if (modified) changed();
        return { matchedCount: 1, modifiedCount: modified ? 1 : 0, upsertedId: null };
      },
      async updateMany(filter, update) {
        const found = select(entry, filter);
        const updated = found.map((doc) => applyUpdate(doc, update, false));
        let modifiedCount = 0;
        found.forEach((doc, position) => {
          if (replace(entry, doc, updated[position])) modifiedCount++;
        });
        if (found.length === 0) applyUpdate({ _id: "" }, update, true);
        if (modifiedCount) changed();
        return { matchedCount: found.length, modifiedCount };
      },
      async findOneAndUpdate(filter, update, options = {}) {
        const [doc] = select(entry, filter, { sort: options.sort, limit: 1 });
        if (!doc) {
          if (!options.upsert) {
            applyUpdate({ _id: "" }, update, true);
            return null;
          }
          const created = upsert(entry, filter, update);
          changed();
          return options.returnDocument === "after" ? copy(created) : null;
        }
        const next = applyUpdate(doc, update, false);
        if (replace(entry, doc, next)) changed();
        return copy(options.returnDocument === "after" ? next : doc);
      },
      async deleteOne(filter) {
        const [doc] = select(entry, filter, { limit: 1 });
        if (!doc) return { deletedCount: 0 };
        entry.docs.splice(entry.docs.indexOf(doc), 1);
        changed();
        return { deletedCount: 1 };
      },
      async deleteMany(filter) {
        const found = new Set(select(entry, filter));
        if (found.size === 0) return { deletedCount: 0 };
        entry.docs = entry.docs.filter((doc) => !found.has(doc));
        changed();
        return { deletedCount: found.size };
      },
      async createIndexes(indexes) {
        if (!Array.isArray(indexes)) fail("invalid-filter", "createIndexes takes a list");
        const specs = indexes.map(checkIndex);
        for (const spec of specs) {
          if (spec.unique) {
            const seen: unknown[][] = [];
            for (const doc of entry.docs) {
              const key = indexKey(doc, spec);
              if (!key) continue;
              if (seen.some((other) => other.every((value, position) => same(value, key[position])))) {
                fail("duplicate-key", `existing documents repeat ${JSON.stringify(Object.keys(spec.key))}`);
              }
              seen.push(key);
            }
          }
        }
        let added = false;
        for (const spec of specs) {
          const position = entry.indexes.findIndex((index) => sameKey(index.key, spec.key));
          if (position === -1) {
            entry.indexes.push(spec);
            added = true;
          } else if (!same(entry.indexes[position], spec)) {
            entry.indexes[position] = spec;
            added = true;
          }
        }
        if (added) changed();
        sweep(entry);
      },
      async listIndexes() {
        return copy(entry.indexes);
      },
    };
    return api as unknown as Collection<T>;
  }

  return {
    collection,
    names: () => [...tables.keys()].filter((name) => tables.get(name)!.docs.length || tables.get(name)!.indexes.length).sort(),
    exportAll() {
      const list = [...tables.entries()].map(([name, entry]) => {
        sweep(entry);
        return { name, indexes: entry.indexes, docs: entry.docs };
      });
      return exportLines(list);
    },
    importAll(ndjson) {
      const lines = parseLines(ndjson);
      const touched = new Set<string>();
      let records = 0;
      const staged = new Map<string, Table>();
      for (const line of lines) {
        const current = staged.get(line.collection) ?? copy(table(line.collection));
        staged.set(line.collection, current);
        touched.add(line.collection);
        if (line.index) {
          const position = current.indexes.findIndex((index) => sameKey(index.key, line.index!.key));
          if (position === -1) current.indexes.push(line.index);
          else current.indexes[position] = line.index;
        } else {
          insert(current, line.document);
          records++;
        }
      }
      for (const [name, entry] of staged) {
        for (const index of entry.indexes.filter((item) => item.unique)) {
          const keys: unknown[][] = [];
          for (const doc of entry.docs) {
            const key = indexKey(doc, index);
            if (!key) continue;
            if (keys.some((other) => other.every((value, position) => same(value, key[position])))) {
              fail("duplicate-key", `imported documents repeat ${JSON.stringify(Object.keys(index.key))} in ${name}`);
            }
            keys.push(key);
          }
        }
      }
      for (const [name, entry] of staged) tables.set(name, entry);
      if (lines.length) changed();
      return { collections: touched.size, records };
    },
    clear() {
      tables.clear();
      changed();
    },
    dropIndex(name, key) {
      const entry = tables.get(name);
      const position = entry ? entry.indexes.findIndex((index) => sameKey(index.key, key)) : -1;
      if (!entry || position === -1) return false;
      entry.indexes.splice(position, 1);
      changed();
      return true;
    },
  };
}
