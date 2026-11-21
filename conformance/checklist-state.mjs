// A reviewer attaches a test covering the whole task. New or incomplete nested
// requirements keep that task open even when its existing scenarios all pass.
export function renderChecklist(lines) {
  const rendered = [];
  const nodes = [];
  const ancestors = [];
  for (const line of lines) {
    const text = typeof line === "string" ? line : line.text;
    const index = rendered.push(text) - 1;
    const task = text.match(/^( *)- \[([ x])\] /);
    if (!task) {
      if (text.trim()) ancestors.length = 0;
      continue;
    }
    const depth = task[1].length;
    while (ancestors.length && ancestors.at(-1).depth >= depth) ancestors.pop();
    const node = { index, depth, wholeTest: line.wholeTest, checked: task[2] === "x", parent: ancestors.at(-1), openChildren: false };
    nodes.push(node);
    ancestors.push(node);
  }
  for (const node of nodes.reverse()) {
    if (node.wholeTest && !node.openChildren) {
      rendered[node.index] = rendered[node.index].replace("- [ ] ", "- [x] ") + " (" + node.wholeTest + ")";
      node.checked = true;
    }
    if (node.parent && (!node.checked || node.openChildren)) node.parent.openChildren = true;
  }
  return rendered.join("\n");
}
