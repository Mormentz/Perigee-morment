import type { Metadata } from "next";
import Link from "next/link";
import {
  buildVaultMetadata,
  buildVaultJsonLd,
  fetchVaultData,
} from "@/lib/vault-metadata";

interface PageProps {
  params: Promise<{ id: string }> | { id: string };
  searchParams?: Promise<{ [key: string]: string | string[] | undefined }> | { [key: string]: string | string[] | undefined };
}

/**
 * Dynamic metadata generator for vault detail pages.
 * Injects dynamic Open Graph and Twitter Card tags containing vault name, balance, and APY.
 */
export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const resolvedParams = await params;
  const id = resolvedParams.id;
  const vault = await fetchVaultData(id);
  return buildVaultMetadata(vault, id);
}

/**
 * App Router dynamic vault detail page with Schema.org JSON-LD structured data.
 */
export default async function VaultDetailPage({ params }: PageProps) {
  const resolvedParams = await params;
  const id = resolvedParams.id;
  const vault = await fetchVaultData(id);
  const jsonLd = buildVaultJsonLd(vault, id);

  if (!vault) {
    return (
      <main className="min-h-screen bg-slate-950 px-4 py-12 text-slate-100 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <h1 className="text-3xl font-bold text-red-400">Vault Not Found</h1>
          <p className="mt-4 text-slate-400">
            The vault with ID <span className="font-mono text-cyan-400">{id}</span> could not be found.
          </p>
          <div className="mt-8">
            <Link
              href="/"
              className="inline-flex items-center rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 transition-colors"
            >
              &larr; Return Home
            </Link>
          </div>
        </div>
      </main>
    );
  }

  return (
    <>
      {/* Search Engine Structured Data (JSON-LD) */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      <main className="min-h-screen bg-slate-950 text-slate-100">
        <header className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
            <div>
              <Link href="/" className="text-2xl font-bold text-cyan-400 hover:text-cyan-300">
                Perigee
              </Link>
              <span className="ml-3 text-xs uppercase tracking-wider text-slate-500">
                Vault Details
              </span>
            </div>
            <Link
              href="/"
              className="text-sm font-medium text-slate-400 hover:text-cyan-400 transition-colors"
            >
              &larr; Back to Dashboard
            </Link>
          </div>
        </header>

        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          {/* Breadcrumb */}
          <nav className="mb-6 flex items-center gap-2 text-xs text-slate-500">
            <Link href="/" className="hover:text-slate-400">Home</Link>
            <span>/</span>
            <span className="text-slate-400">Vaults</span>
            <span>/</span>
            <span className="font-mono text-cyan-400">{vault.id}</span>
          </nav>

          {/* Vault Title & Status */}
          <div className="flex flex-col gap-4 border-b border-slate-800 pb-6 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-3xl font-bold text-white">{vault.name}</h1>
                <span
                  className={`inline-block rounded-full px-3 py-1 text-xs font-semibold ${
                    vault.status === "ACTIVE"
                      ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                      : "bg-amber-950 text-amber-400 border border-amber-800"
                  }`}
                >
                  {vault.status}
                </span>
              </div>
              <p className="mt-1 font-mono text-xs text-slate-400">
                Vault ID: {vault.id}
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                className="rounded-lg bg-slate-800 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700 transition-colors"
              >
                Withdraw
              </button>
              <button
                type="button"
                className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 transition-colors shadow-lg shadow-cyan-900/30"
              >
                Deposit Funds
              </button>
            </div>
          </div>

          {/* Key Metrics Cards */}
          <div className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
              <p className="text-xs font-medium text-slate-400">Total Balance</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {vault.balance.toLocaleString()}{" "}
                <span className="text-sm font-normal text-cyan-400">{vault.asset}</span>
              </p>
              <p className="mt-1 text-xs text-slate-500">Custodied in policy contract</p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
              <p className="text-xs font-medium text-slate-400">Projected APY</p>
              <p className="mt-2 text-2xl font-bold text-emerald-400">
                {vault.apy !== undefined ? `${vault.apy}%` : "0.0%"}
              </p>
              <p className="mt-1 text-xs text-emerald-500/80">Autonomous yield strategy</p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
              <p className="text-xs font-medium text-slate-400">Underlying Asset</p>
              <p className="mt-2 text-2xl font-bold text-white">{vault.asset || "XLM"}</p>
              <p className="mt-1 text-xs text-slate-500">Stellar Network Asset</p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
              <p className="text-xs font-medium text-slate-400">Manager / Owner</p>
              <p className="mt-2 truncate font-mono text-sm font-medium text-slate-300">
                {vault.owner}
              </p>
              <p className="mt-1 text-xs text-slate-500">Verified Protocol Manager</p>
            </div>
          </div>

          {/* Strategy Details */}
          <div className="mt-8 rounded-xl border border-slate-800 bg-slate-900/40 p-6">
            <h2 className="text-lg font-semibold text-white">Vault Overview & Automation</h2>
            <p className="mt-2 text-sm text-slate-400 leading-relaxed">
              This vault operates autonomously on Soroban smart contracts. Yield is auto-compounded,
              and allocations are guarded by strict emergency circuit breakers and multi-sig verification.
            </p>
            <div className="mt-6 flex flex-wrap items-center gap-4 text-xs text-slate-400">
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
                <span>Open Graph Metadata Active</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
                <span>Schema.org FinancialProduct Indexed</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-purple-400"></span>
                <span>Soroban Smart Contract Guarded</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
