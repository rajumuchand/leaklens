import SupabaseAuth from '@/components/SupabaseAuth';

/**
 * Login page – shows the Supabase authentication UI.
 * Previously this page performed a server‑side redirect to an
 * external Framer login URL, which resulted in a placeholder note
 * being displayed.  The redirect has been removed so the page now
 * renders the real login component.
 */
export default function Login() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', marginTop: '4rem' }}>
      <SupabaseAuth redirectUrl={typeof window !== 'undefined' ? window.location.origin : ''} />
    </div>
  );
}

