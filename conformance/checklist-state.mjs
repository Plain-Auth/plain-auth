// A reviewer attaches a test covering the whole task. New or incomplete nested
// requirements keep that task open even when its existing scenarios all pass.
// Items marked not applicable render as plain bullets and are left out of the
// totals without detaching later siblings from their parent.
export function checklistReport(lines) {
  const counts = { verified: 0, partial: 0, unverified: 0, scenarios: 0, notApplicable: 0 };
  const rendered = [];
  const nodes = [];
  const ancestors = [];
  for (const line of lines) {
    if (typeof line === "object" && line.notApplicable !== undefined) {
      const text = line.text.replace(/^( *)- \[ \] /, "$1- ");
      rendered.push(line.notApplicable ? text + " — *" + line.notApplicable + "*" : text);
      counts.notApplicable++;
      continue;
    }
    const text = typeof line === "string" ? line : line.text;
    const index = rendered.push(text) - 1;
    const task = text.match(/^( *)- \[([ x])\] /);
    if (!task) {
      if (text.trim()) ancestors.length = 0;
      continue;
    }
    const depth = task[1].length;
    while (ancestors.length && ancestors.at(-1).depth >= depth) ancestors.pop();
    const node = { index, depth, wholeTest: line.wholeTest, checked: task[2] === "x", parent: ancestors.at(-1), openChildren: false, testedChild: false };
    nodes.push(node);
    ancestors.push(node);
  }
  for (const node of nodes.reverse()) {
    // Rows checked when inserted are passing scenarios. Inventory rows start
    // open and close only when the reviewer and all their children agree.
    const scenario = node.checked;
    if (node.wholeTest && !node.openChildren) {
      rendered[node.index] = rendered[node.index].replace("- [ ] ", "- [x] ") + " (" + node.wholeTest + ")";
      node.checked = true;
    }
    if (scenario) counts.scenarios++;
    else if (node.checked) counts.verified++;
    else if (node.testedChild) counts.partial++;
    else counts.unverified++;
    if (node.parent) {
      if (!node.checked || node.openChildren) node.parent.openChildren = true;
      if (node.checked || node.testedChild) node.parent.testedChild = true;
    }
  }
  return { markdown: rendered.join("\n"), counts };
}
