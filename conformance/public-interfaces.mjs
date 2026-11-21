import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import ts from "typescript";

const sort = (names) => [...new Set(names)].sort();
const privateSource = /\.(?:test|spec|typecheck)\.[cm]?tsx?$/;

export function readInterfaces(root, tracked) {
  root = resolve(root);
  const files = new Set(tracked);
  const packages = [];
  const paths = {};
  for (const source of tracked.filter(f => /^packages\/[^/]+\/package\.json$/.test(f))) {
    const meta = JSON.parse(readFileSync(join(root, source), "utf8"));
    const pkg = { source, name: meta.name, version: meta.version, private: !!meta.private, exports: Object.keys(meta.exports ?? {}), commands: Object.keys(meta.bin ?? {}), entries: [] };
    packages.push(pkg);
    for (const [subpath, target] of Object.entries(meta.exports ?? {})) {
      const selection = typeof target === "string" ? target : target["dev-source"] ?? target.default;
      const src = selection.replace(/^\.\/dist\//, "./src/").replace(/\.mjs$/, ".ts");
      const pattern = join(dirname(source), src);
      const [before, after] = pattern.split("*");
      const matches = after === undefined ? [pattern] : tracked.filter(f => f.startsWith(before) && f.endsWith(after) && !privateSource.test(f) && !f.slice(before.length, -after.length).includes("/"));
      assert.ok(matches.length, "Export pattern has no sources: " + pattern);
      const conditions = typeof target === "object" ? Object.keys(target).filter(k => !["dev-source", "types", "default"].includes(k)) : [];
      for (const file of matches) {
        assert.ok(files.has(file), "Published entry source is missing: " + file);
        const key = after === undefined ? subpath : subpath.replace("*", file.slice(before.length, -after.length));
        const specifier = pkg.name + (key === "." ? "" : "/" + key.slice(2));
        paths[specifier] = [file];
        const alternatives = {};
        for (const condition of conditions) {
          if (target[condition] === target.default) continue;
          const implementation = join(dirname(source), target[condition].replace(/^\.\/dist\//, "./src/").replace(/\.mjs$/, ".ts"));
          assert.ok(files.has(implementation), "Unresolved conditional export " + implementation);
          alternatives[condition] = implementation;
        }
        pkg.entries.push({ subpath: key, ...(after === undefined ? {} : { pattern: subpath }), file, conditions, ...(Object.keys(alternatives).length ? { alternatives } : {}), symbols: [] });
      }
    }
  }
  // Plugin option types and server-only operations can live behind a factory,
  // so retain all source modules when resolving the published declarations.
  const production = tracked.filter(f => f.startsWith("packages/") && f.includes("/src/") && /\.tsx?$/.test(f) && !privateSource.test(f));
  const opts = { target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, jsx: ts.JsxEmit.Preserve, skipLibCheck: true, noEmit: true, types: [], baseUrl: root, paths };
  const program = ts.createProgram(production.map(f => resolve(root, f)), opts);
  const checker = program.getTypeChecker();
  const published = new Map();
  const sourceFile = f => program.getSourceFile(resolve(root, f));
  function origin(decl) {
    const file = decl.getSourceFile();
    return { file: relative(root, file.fileName), line: file.getLineAndCharacterOfPosition(decl.getStart(file)).line + 1 };
  }
  function exportsOf(file) {
    const ast = sourceFile(file);
    if (!ast) return [];
    const module = checker.getSymbolAtLocation(ast);
    if (!module) return [];
    return checker.getExportsOfModule(module).map(symbol => {
      const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
      const decl = target.declarations?.[0] ?? symbol.declarations?.[0];
      return { name: symbol.name, symbol: target, ...(decl ? origin(decl) : {file, line: 1}) };
    }).filter(s => !s.name.startsWith("__") && s.name !== "PACKAGE_VERSION");
  }
  // External star exports are separately owned, often type-only contracts.
  // Keep their coordinates even when a dependency is absent from this checkout.
  function externalForwards(file, visited = new Set()) {
    if (visited.has(file)) return [];
    visited.add(file);
    const forwards = [];
    for (const stmt of sourceFile(file)?.statements ?? []) {
      if (!ts.isExportDeclaration(stmt) || stmt.exportClause || !stmt.moduleSpecifier) continue;
      const specifier = stmt.moduleSpecifier.text;
      const linked = checker.getSymbolAtLocation(stmt.moduleSpecifier)?.declarations?.[0];
      if (linked && ts.isSourceFile(linked)) {
        forwards.push(...externalForwards(relative(root, linked.fileName), visited));
      } else {
        assert.ok(!specifier.startsWith(".") && !paths[specifier], "Unresolved source re-export " + file + " -> " + specifier);
        forwards.push((stmt.isTypeOnly ? "types " : "exports ") + specifier);
      }
    }
    return sort(forwards);
  }
  for (const pkg of packages) {
    for (const entry of pkg.entries) {
      const symbols = exportsOf(entry.file);
      entry.symbols = sort(symbols.map(s => s.name));
      const forwarded = externalForwards(entry.file);
      if (forwarded.length) entry.externalForwards = forwarded;
      for (const s of symbols) {
        if (!published.has(s.file)) published.set(s.file, new Map());
        published.get(s.file).set(s.name, s);
      }
    }
  }
  function members(symbol) {
    const type = checker.getDeclaredTypeOfSymbol(symbol);
    // Union variants can each have fields that never appear on the common type.
    const types = type.isUnion() ? type.types : [type];
    const properties = new Map();
    for (const t of types) {
      for (const property of checker.getPropertiesOfType(t)) {
        const decl = property.declarations?.[0];
        if (decl && !properties.has(property.name)) properties.set(property.name, {name: property.name, ...origin(decl)});
      }
    }
    return [...properties.values()].filter(p => p.file.startsWith("packages/") && !p.name.startsWith("__"));
  }
  function returnedFields(symbol) {
    const decl = symbol.valueDeclaration;
    if (!decl) return [];
    const type = checker.getTypeOfSymbolAtLocation(symbol, decl);
    const signatures = type.getCallSignatures();
    return sort(signatures.flatMap(sig => checker.getPropertiesOfType(sig.getReturnType()).map(s => s.name)));
  }
  function declarationExports(file) {
    const ast = sourceFile(file);
    const out = new Map(published.get(file) ?? []);
    for (const statement of ast?.statements ?? []) {
      if (!ts.getModifiers(statement)?.some(mod => mod.kind === ts.SyntaxKind.ExportKeyword)) continue;
      const declarations = ts.isVariableStatement(statement) ? statement.declarationList.declarations : [statement];
      for (const decl of declarations) {
        if (!decl.name || !ts.isIdentifier(decl.name) || decl.name.text === "PACKAGE_VERSION") continue;
        const symbol = checker.getSymbolAtLocation(decl.name);
        if (symbol && !out.has(symbol.name)) out.set(symbol.name, {name: symbol.name, symbol, ...origin(decl)});
      }
    }
    return [...out.values()];
  }
  function serverOperations(file) {
    const ast = sourceFile(file);
    const result = [];
    function visit(node) {
      if (ts.isCallExpression(node) && node.arguments[0] && ts.isObjectLiteralExpression(node.arguments[0]) && ["createAuthEndpoint", "createAuthEndpoint.serverOnly"].includes(node.expression.getText(ast))) {
        // The pathless overload registers a callable server API without an HTTP path.
        let name;
        for (let parent = node.parent; parent; parent = parent.parent) {
          if ((ts.isFunctionDeclaration(parent) || ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent)) && parent.name && ts.isIdentifier(parent.name)) {
            name = parent.name.text;
            break;
          }
        }
        assert.ok(name, "Unresolved server-only operation in " + file);
        if (name.endsWith("Endpoint")) name = name.replace(/Endpoint$/, "").replace(/^create([A-Z])/, (_, c) => c.toLowerCase());
        result.push({name, ...origin(node)});
      }
      ts.forEachChild(node, visit);
    }
    if (ast) visit(ast);
    return result;
  }
  return {packages, exportsOf, members, returnedFields, declarationExports, published, serverOperations};
}

export function documentedDialects(content) {
  const sections = new Map();
  let heading;
  for (const line of content.split("\n")) {
    if (line.startsWith("## ")) { heading = line.slice(3); sections.set(heading, []); }
    const match = line.match(/^\s*[*-] \[([^\]]+)\]\(([^)]+)\)/);
    if (match && heading) sections.get(heading).push({ name: match[1], url: match[2] });
  }
  return sections;
}

export function readCommunityAdapters(content) {
  const ast = ts.createSourceFile("community-adapters.ts", content, ts.ScriptTarget.Latest, true);
  for (const stmt of ast.statements.filter(ts.isVariableStatement)) {
    for (const decl of stmt.declarationList.declarations) {
      if (decl.name.getText(ast) !== "communityAdapters" || !ts.isArrayLiteralExpression(decl.initializer)) continue;
      return decl.initializer.elements.map(item => {
        const value = key => {
          const prop = item.properties.find(p => p.name.getText(ast) === key);
          assert.ok(prop && ts.isStringLiteral(prop.initializer), "Missing community adapter " + key);
          return prop.initializer.text;
        };
        return { name: value("name"), database: value("database"), url: value("url") };
      });
    }
  }
  throw Error("No community adapter registry");
}
