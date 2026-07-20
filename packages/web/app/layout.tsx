import "./globals.css";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";

// next/font self-hosts these at build time — no runtime request to Google,
// no layout shift, and the app still works with no external network.
const grotesk = Space_Grotesk({
  subsets: ["latin"], weight: ["400", "500", "700"], variable: "--font-sans",
});
const mono = JetBrains_Mono({
  subsets: ["latin"], weight: ["400", "500", "700"], variable: "--font-mono",
});

export const metadata = {
  title: "Blackout — Attack Surface Management",
  description: "Map, score, and monitor your external attack surface.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${grotesk.variable} ${mono.variable}`}>
      <body
        style={{
          fontFamily: "var(--font-sans), var(--sans)",
        }}
      >
        {children}
      </body>
    </html>
  );
}
