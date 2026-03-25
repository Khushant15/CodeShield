/**
 * 404 Not Found Handler
 */
export function notFound(req, res) {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found.` });
}
