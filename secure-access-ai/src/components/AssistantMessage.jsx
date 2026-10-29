const INLINE_PATTERN = /(`[^`]+`|\*\*.+?\*\*|\*[^*]+\*|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g;

function renderInline(text, keyPrefix) {
  return text.split(INLINE_PATTERN).filter(Boolean).map((part, index) => {
    const key = `${keyPrefix}-${index}`;
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={key}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={key}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("*") && part.endsWith("*")) {
      return <em key={key}>{part.slice(1, -1)}</em>;
    }
    const link = part.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/);
    if (link) {
      return (
        <a href={link[2]} key={key} rel="noopener noreferrer" target="_blank">
          {link[1]}
        </a>
      );
    }
    return part;
  });
}

function parseTableRow(line) {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function AssistantMessage({ text }) {
  const lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let paragraph = [];
  let index = 0;
  let blockIndex = 0;

  function flushParagraph() {
    if (paragraph.length === 0) return;
    const paragraphKey = blockIndex++;
    blocks.push(
      <p key={`paragraph-${paragraphKey}`}>
        {renderInline(paragraph.join(" "), `paragraph-inline-${paragraphKey}`)}
      </p>,
    );
    paragraph = [];
  }

  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) {
      flushParagraph();
      index += 1;
      continue;
    }

    if (line.trimStart().startsWith("```")) {
      flushParagraph();
      const codeLines = [];
      index += 1;
      while (index < lines.length && !lines[index].trimStart().startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push(
        <pre key={`code-${index}`}>
          <code>{codeLines.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    const tableDivider = lines[index + 1]?.match(
      /^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$/,
    );
    if (line.includes("|") && tableDivider) {
      flushParagraph();
      const headers = parseTableRow(line);
      index += 2;
      const rows = [];
      while (index < lines.length && lines[index].includes("|") && lines[index].trim()) {
        rows.push(parseTableRow(lines[index]));
        index += 1;
      }
      blocks.push(
        <div className="ai-markdown-table" key={`table-${index}`}>
          <table>
            <thead>
              <tr>
                {headers.map((cell, cellIndex) => (
                  <th key={`table-header-${cellIndex}`}>
                    {renderInline(cell, `table-header-inline-${cellIndex}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIndex) => (
                <tr key={`table-row-${rowIndex}`}>
                  {headers.map((_, cellIndex) => (
                    <td key={`table-cell-${cellIndex}`}>
                      {renderInline(row[cellIndex] || "", `table-inline-${rowIndex}-${cellIndex}`)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    const heading = line.match(/^\s{0,3}(#{1,3})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      const Heading = `h${heading[1].length}`;
      blocks.push(
        <Heading key={`heading-${index}`}>
          {renderInline(heading[2], `heading-inline-${index}`)}
        </Heading>,
      );
      index += 1;
      continue;
    }

    const listItem = line.match(/^\s*(?:[-*+]\s+|(\d+)\.\s+)(.+)$/);
    if (listItem) {
      flushParagraph();
      const ordered = Boolean(listItem[1]);
      const items = [];
      while (index < lines.length) {
        const item = lines[index].match(/^\s*(?:[-*+]\s+|(\d+)\.\s+)(.+)$/);
        if (!item || Boolean(item[1]) !== ordered) break;
        items.push(
          <li key={`list-item-${index}`}>
            {renderInline(item[2], `list-inline-${index}`)}
          </li>,
        );
        index += 1;
      }
      const List = ordered ? "ol" : "ul";
      blocks.push(<List key={`list-${index}`}>{items}</List>);
      continue;
    }

    paragraph.push(line.trim());
    index += 1;
  }

  flushParagraph();
  return <div className="ai-markdown-message">{blocks}</div>;
}

export default AssistantMessage;
