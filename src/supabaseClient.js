import { createClient } from '@supabase/supabase-js';

const supabaseUrl =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_SUPABASE_URL) ||
  'https://fpidtcofamgfyyiwyshy.supabase.co';

const supabasePublishableKey =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY) ||
  'sb_publishable_g4OZs168BBOG7KkUOAj1ng_ZCHTXmBY';

export const supabase = createClient(supabaseUrl, supabasePublishableKey);
