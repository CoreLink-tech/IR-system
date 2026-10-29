import LandingPage from '@/components/landing-page';

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ from?: string }>;
}) {
  const params = await searchParams;
  return <LandingPage hideGetApp={params.from === 'apk'} />;
}
