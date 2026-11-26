import { GetServerSideProps } from 'next'

/**
 * Redirects visitors to the external Framer login page.
 * This page is used as the entry point for Google authentication
 * without requiring any local tunnel.
 */
export const getServerSideProps: GetServerSideProps = async () => {
  return {
    redirect: {
      destination: 'https://linklenslogin.framer.website/',
      permanent: false,
    },
  }
}

export default function Login() {
  // This component will never be rendered because of the redirect.
  return null
}
