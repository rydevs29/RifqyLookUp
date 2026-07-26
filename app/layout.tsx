import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "RifqyLookup | OSINT Tool",
  description: "Advanced OSINT and Reconnaissance Tool by Rifqy",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="id">
      <body>{children}</body>
    </html>
  );
}
