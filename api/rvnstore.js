export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { endpoint, method, body, authToken } = req.body;
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers['X-Authorization'] = authToken;

  try {
    const response = await fetch(`https://4AE9.playfabapi.com${endpoint}`, {
      method: method || 'POST',
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
    const result = await response.json();
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}