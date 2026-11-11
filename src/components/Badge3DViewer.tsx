import React, { useState } from 'react';
import { Award, Eye, RotateCcw, ShieldCheck } from 'lucide-react';
import { DestinationRecord } from '../types/platform';

interface Badge3DViewerProps {
  destination: DestinationRecord;
  verificationId?: string;
  holderName?: string;
  completionDate?: string;
  compact?: boolean;
}

export const Badge3DViewer: React.FC<Badge3DViewerProps> = ({
  destination,
  verificationId,
  holderName,
  completionDate,
  compact = false,
}) => {
  const [rotX, setRotX] = useState<number>(12);
  const [rotY, setRotY] = useState<number>(-16);
  const [renderMode, setRenderMode] = useState<'3D_INTERACTIVE' | '2D_VECTOR'>('3D_INTERACTIVE');

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (renderMode === '2D_VECTOR') return;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setRotY(Math.round(x * 38));
    setRotX(Math.round(-y * 32));
  };

  const handleReset = () => {
    setRotX(12);
    setRotY(-16);
  };

  const is8000m = destination.elevationM >= 8000;

  return (
    <div className="bg-[#121214] border border-[#C9A86A]/25 rounded-xl p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-3 mb-4">
        <div>
          <p className="text-xs text-[#A1A1AA] font-mono-tabular">
            {destination.badgeIdentity.badgeCode} · {destination.code}
          </p>
          <h4 className="text-sm font-semibold text-white mt-0.5">
            {destination.badgeIdentity.badgeTitle}
          </h4>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={() =>
              setRenderMode((prev) =>
                prev === '3D_INTERACTIVE' ? '2D_VECTOR' : '3D_INTERACTIVE'
              )
            }
            className="px-2.5 py-1 text-xs font-medium text-[#C9A86A] bg-[#18181B] border border-[#C9A86A]/30 rounded hover:border-[#FFD700] transition-colors whitespace-nowrap shrink-0 flex items-center gap-1"
            title="Switch between Interactive 3D Relief and Accessible 2D Vector Emblem"
          >
            <Eye className="w-3.5 h-3.5" />
            <span>{renderMode === '3D_INTERACTIVE' ? '2D Vector' : '3D Relief'}</span>
          </button>
          {renderMode === '3D_INTERACTIVE' && (
            <button
              type="button"
              onClick={handleReset}
              className="p-1.5 text-xs text-[#A1A1AA] bg-[#18181B] border border-white/10 rounded hover:text-white transition-colors"
              title="Reset 3D orientation"
              aria-label="Reset 3D orientation"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Interactive 3D / 2D Emblem Stage */}
      <div
        onPointerMove={handlePointerMove}
        onPointerLeave={handleReset}
        className={`relative flex items-center justify-center ${
          compact ? 'h-52' : 'h-64'
        } select-none touch-none cursor-grab active:cursor-grabbing rounded-lg bg-gradient-to-b from-[#0A0A0A] via-[#141417] to-[#0A0A0A] border border-white/5 overflow-hidden`}
        style={{ perspective: '900px' }}
      >
        {/* Subtle topographic contour rings background */}
        <svg
          className="absolute inset-0 w-full h-full opacity-15 pointer-events-none"
          viewBox="0 0 200 200"
          aria-hidden="true"
        >
          <circle cx="100" cy="100" r="88" fill="none" stroke="#C9A86A" strokeWidth="0.5" strokeDasharray="3 3" />
          <circle cx="100" cy="100" r="72" fill="none" stroke="#C9A86A" strokeWidth="0.5" />
          <circle cx="100" cy="100" r="56" fill="none" stroke="#C9A86A" strokeWidth="0.4" strokeDasharray="6 2" />
        </svg>

        <div
          className="relative transition-transform duration-150 ease-out"
          style={{
            transform:
              renderMode === '3D_INTERACTIVE'
                ? `rotateX(${rotX}deg) rotateY(${rotY}deg)`
                : 'none',
            transformStyle: 'preserve-3d',
          }}
        >
          {/* Outer Octagonal / Circular Metallic Gold Medallion */}
          <div
            className={`relative ${
              compact ? 'w-40 h-40' : 'w-48 h-48'
            } rounded-full flex flex-col items-center justify-center text-center p-4 shadow-2xl border-2 ${
              is8000m
                ? 'border-[#FFD700] bg-gradient-to-br from-[#3A2E18] via-[#0E0E11] to-[#292010]'
                : 'border-[#C9A86A] bg-gradient-to-br from-[#241E14] via-[#0B0B0D] to-[#1C170F]'
            }`}
            style={{
              boxShadow:
                renderMode === '3D_INTERACTIVE'
                  ? `${-rotY * 0.6}px ${rotX * 0.6 + 10}px 28px rgba(0,0,0,0.85), inset 0 0 22px rgba(201,168,106,0.28)`
                  : '0 10px 25px rgba(0,0,0,0.8)',
            }}
          >
            {/* Inner Engraved Rim */}
            <div className="absolute inset-2 rounded-full border border-[#C9A86A]/45 pointer-events-none" />
            <div className="absolute inset-3.5 rounded-full border border-dashed border-[#FFD700]/25 pointer-events-none" />

            {/* Top Origin Crest */}
            <span className="text-[10px] tracking-widest uppercase text-[#C9A86A] font-mono-tabular">
              0 TO 8848 · {destination.countryIsoCodes.join('/')}
            </span>

            {/* Mountain Relief SVG Vector */}
            <svg
              className="w-16 h-11 my-1.5 text-[#FFD700]"
              viewBox="0 0 120 70"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M8 62L42 16L62 40L82 10L112 62H8Z"
                stroke="currentColor"
                strokeWidth="2.2"
                fill="rgba(201,168,106,0.16)"
              />
              <path
                d="M42 16L50 34L40 42M82 10L74 30L86 38"
                stroke="#C9A86A"
                strokeWidth="1.3"
              />
              <line x1="4" y1="62" x2="116" y2="62" stroke="#FFD700" strokeWidth="1.5" />
            </svg>

            {/* Destination Name & Verified Elevation */}
            <p className="font-display text-xs font-bold text-white leading-tight line-clamp-1 px-2">
              {destination.officialNameEn.split(' (')[0]}
            </p>
            {destination.officialNameNe && (
              <p className="font-nepali text-[11px] text-[#C9A86A] leading-tight mt-0.5">
                {destination.officialNameNe}
              </p>
            )}
            <p className="font-mono-tabular text-xs font-semibold text-[#FFD700] mt-1">
              {destination.elevationM.toLocaleString()} m · {destination.elevationFt.toLocaleString()} ft
            </p>

            {/* Bottom Verification Stamp */}
            <div className="mt-1.5 flex items-center gap-1 text-[10px] text-emerald-400 font-mono-tabular">
              <ShieldCheck className="w-3 h-3 shrink-0" />
              <span>EARNED · HUMAN VERIFIED</span>
            </div>
          </div>
        </div>
      </div>

      {/* Provenance Footer */}
      <div className="mt-3 pt-3 border-t border-white/10 flex flex-wrap items-center justify-between gap-2 text-xs text-[#A1A1AA]">
        <div className="flex items-center gap-1.5">
          <Award className="w-3.5 h-3.5 text-[#C9A86A]" />
          <span>Non-Transferable Earned Credential</span>
        </div>
        {verificationId ? (
          <span className="font-mono-tabular text-[#C9A86A]">{verificationId}</span>
        ) : (
          <span className="font-mono-tabular">
            {holderName ? `${holderName} · ${completionDate}` : 'Free Upon Human Verification'}
          </span>
        )}
      </div>
    </div>
  );
};
