export const VSCHAR = /[\x20-\x7e]/;
export const NQCHAR = /[\x21\x23-\x5b\x5d-\x7e]/;
export const NQSCHAR = /[\x20\x21]/;
export const UNICODECHARNOCRLF =
  /[\x20-\x7e\x80-\ud7ff\ue000-\ufffd\u{10000}-\u{10FFFF}]/u;

const SNAKE_START = /([_-][a-z])/g;
function snakeStart(value: string): string {
  return value.slice(1).toUpperCase();
}
export function camelCase(value: string): string {
  return value.toLowerCase().replace(SNAKE_START, snakeStart);
}

const CAMEL_START = /([A-Z])/g;
function camelStart(value: string): string {
  return `_${value.toLowerCase()}`;
}
export function snakeCase(value: string): string {
  const result: string = value.replace(CAMEL_START, camelStart);
  return result[0] === "_" ? result.slice(1) : result;
}
