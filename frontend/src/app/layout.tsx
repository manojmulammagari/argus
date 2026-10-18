import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const code = JetBrains_Mono({ subsets: ["latin"], variable: "--font-code" });

export const metadata: Metadata = {
  title: "ARGUS — Autonomous DevSecOps Intelligence",
  description:
    "Six autonomous AI agents audit live GitHub pull requests for vulnerabilities, compliance risk, and exploitable attack chains — then write the patch.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.variable} ${code.variable} ${inter.className} antialiased`}>
        {children}
      </body>
    </html>
  );
}
