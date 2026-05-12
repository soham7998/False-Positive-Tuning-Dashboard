import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'False Positive Tuning Dashboard',
  description: 'Automated SOC alert tuning — identify FP patterns and reduce analyst fatigue',
  keywords: ['SOC', 'False Positive', 'Alert Tuning', 'SIEM', 'Cybersecurity'],
  authors: [{ name: 'Soham Shah' }],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
