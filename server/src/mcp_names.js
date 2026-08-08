export function mcpToolName(tool) {
  return /^[a-zA-Z0-9_-]+$/.test(tool?.slug || '') ? tool.slug : `tool_${String(tool?._id || '')}`;
}
