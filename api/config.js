export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.status(200).json({
    supabaseUrl: 'https://aqeglcbdaaaixmznyavk.supabase.co',
    supabaseKey: process.env.SUPABASE_ANON_KEY || 'sb_publishable__0lfwQ9FyS4Y2af_2nJisQ_CDTsVHpB'
  });
}