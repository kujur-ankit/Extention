import React, { useState } from 'react';
import { Button, ButtonVariant, ButtonSize } from './Button';

// Sample SVG Icons for icon support demonstrations
const SearchIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
  </svg>
);

const DownloadIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
  </svg>
);

const PlusIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
  </svg>
);

const ArrowRightIcon = () => (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
  </svg>
);

export const ButtonDemo: React.FC = () => {
  // Interactive playground states
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedVariant, setSelectedVariant] = useState<ButtonVariant>('primary');
  const [selectedSize, setSelectedSize] = useState<ButtonSize>('md');
  const [showIcon, setShowIcon] = useState<boolean>(true);
  const [disabled, setDisabled] = useState<boolean>(false);

  return (
    <div className="min-h-screen bg-[#f5f5f5] text-[#1f1f1f] p-6 sm:p-12 font-sans antialiased">
      <div className="max-w-5xl mx-auto space-y-10">
        
        {/* Header */}
        <div className="border-b border-gray-200 pb-6">
          <div className="flex items-center gap-3 mb-2">
            <span className="w-6 h-6 rounded bg-[#1677ff] text-white flex items-center justify-center text-xs font-bold shadow-sm shadow-blue-500/30">
              A
            </span>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900">
              Ant Design Button Component
            </h1>
          </div>
          <p className="text-gray-500 text-sm">
            Production-ready React + Tailwind CSS implementation with pixel-perfect Ant Design v5 aesthetics.
          </p>
        </div>

        {/* 1. All Variants Section */}
        <section className="bg-white rounded-xl p-6 sm:p-8 shadow-sm border border-gray-200/80 space-y-4">
          <h2 className="text-base font-semibold text-gray-900 flex items-center gap-2">
            <span>1. Variants</span>
            <span className="text-xs text-gray-400 font-normal">Primary, Default (Outline), Ghost (Text)</span>
          </h2>
          <div className="flex flex-wrap items-center gap-4 pt-2">
            <Button variant="primary">Primary Button</Button>
            <Button variant="default">Default Button</Button>
            <Button variant="ghost">Ghost Button</Button>
          </div>
        </section>

        {/* 2. Sizes Section */}
        <section className="bg-white rounded-xl p-6 sm:p-8 shadow-sm border border-gray-200/80 space-y-4">
          <h2 className="text-base font-semibold text-gray-900 flex items-center gap-2">
            <span>2. Sizes</span>
            <span className="text-xs text-gray-400 font-normal">Small (sm), Medium (md), Large (lg)</span>
          </h2>
          <div className="space-y-4 pt-2">
            <div className="flex flex-wrap items-center gap-4">
              <Button variant="primary" size="sm">Small (sm)</Button>
              <Button variant="primary" size="md">Medium (md)</Button>
              <Button variant="primary" size="lg">Large (lg)</Button>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <Button variant="default" size="sm">Small (sm)</Button>
              <Button variant="default" size="md">Medium (md)</Button>
              <Button variant="default" size="lg">Large (lg)</Button>
            </div>
          </div>
        </section>

        {/* 3. Icon Support Section */}
        <section className="bg-white rounded-xl p-6 sm:p-8 shadow-sm border border-gray-200/80 space-y-4">
          <h2 className="text-base font-semibold text-gray-900 flex items-center gap-2">
            <span>3. Icon Support</span>
            <span className="text-xs text-gray-400 font-normal">Leading & Trailing icon with gap-2</span>
          </h2>
          <div className="flex flex-wrap items-center gap-4 pt-2">
            <Button variant="primary" icon={<SearchIcon />}>
              Search
            </Button>
            <Button variant="default" icon={<DownloadIcon />}>
              Download File
            </Button>
            <Button variant="ghost" icon={<PlusIcon />}>
              Add Item
            </Button>
            <Button variant="primary" icon={<ArrowRightIcon />} iconPosition="right">
              Continue
            </Button>
          </div>
        </section>

        {/* 4. Loading States Section */}
        <section className="bg-white rounded-xl p-6 sm:p-8 shadow-sm border border-gray-200/80 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <h2 className="text-base font-semibold text-gray-900">4. Loading States</h2>
              <p className="text-xs text-gray-500">
                Shows spinning Tailwind SVG loader, disables pointer events, and maintains button dimensions.
              </p>
            </div>
            <Button 
              variant="default" 
              size="sm" 
              onClick={() => setLoading(!loading)}
            >
              Toggle Loading: <span className="font-bold text-[#1677ff] ml-1">{loading ? 'ON' : 'OFF'}</span>
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <Button variant="primary" isLoading={loading}>
              Submit Request
            </Button>
            <Button variant="default" isLoading={loading} icon={<DownloadIcon />}>
              Exporting Data
            </Button>
            <Button variant="ghost" isLoading={loading}>
              Syncing
            </Button>
            <Button variant="primary" size="sm" isLoading={true}>
              Always Loading (sm)
            </Button>
          </div>
        </section>

        {/* 5. Disabled States */}
        <section className="bg-white rounded-xl p-6 sm:p-8 shadow-sm border border-gray-200/80 space-y-4">
          <h2 className="text-base font-semibold text-gray-900 flex items-center gap-2">
            <span>5. Disabled States</span>
            <span className="text-xs text-gray-400 font-normal">cursor-not-allowed, opacity-60</span>
          </h2>
          <div className="flex flex-wrap items-center gap-4 pt-2">
            <Button variant="primary" disabled>
              Primary Disabled
            </Button>
            <Button variant="default" disabled icon={<DownloadIcon />}>
              Default Disabled
            </Button>
            <Button variant="ghost" disabled>
              Ghost Disabled
            </Button>
          </div>
        </section>

        {/* 6. Interactive Playground */}
        <section className="bg-gradient-to-br from-white to-gray-50 rounded-xl p-6 sm:p-8 shadow-sm border border-gray-200/80 space-y-6">
          <div className="border-b border-gray-200 pb-4">
            <h2 className="text-base font-semibold text-gray-900">6. Interactive Component Playground</h2>
            <p className="text-xs text-gray-500">Customize props in real time to preview button behavior.</p>
          </div>

          {/* Controls */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div>
              <label className="block text-gray-500 font-medium mb-1.5">Variant</label>
              <select
                className="w-full bg-white border border-gray-300 rounded-md p-2 text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500/30"
                value={selectedVariant}
                onChange={(e) => setSelectedVariant(e.target.value as ButtonVariant)}
              >
                <option value="primary">primary</option>
                <option value="default">default</option>
                <option value="ghost">ghost</option>
              </select>
            </div>

            <div>
              <label className="block text-gray-500 font-medium mb-1.5">Size</label>
              <select
                className="w-full bg-white border border-gray-300 rounded-md p-2 text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500/30"
                value={selectedSize}
                onChange={(e) => setSelectedSize(e.target.value as ButtonSize)}
              >
                <option value="sm">sm (Small)</option>
                <option value="md">md (Medium)</option>
                <option value="lg">lg (Large)</option>
              </select>
            </div>

            <div className="flex flex-col justify-end">
              <label className="flex items-center gap-2 cursor-pointer p-2 bg-white rounded-md border border-gray-300">
                <input
                  type="checkbox"
                  checked={showIcon}
                  onChange={(e) => setShowIcon(e.target.checked)}
                  className="rounded text-[#1677ff] focus:ring-blue-500/30"
                />
                <span className="text-gray-700 font-medium">Include Icon</span>
              </label>
            </div>

            <div className="flex flex-col justify-end">
              <label className="flex items-center gap-2 cursor-pointer p-2 bg-white rounded-md border border-gray-300">
                <input
                  type="checkbox"
                  checked={disabled}
                  onChange={(e) => setDisabled(e.target.checked)}
                  className="rounded text-[#1677ff] focus:ring-blue-500/30"
                />
                <span className="text-gray-700 font-medium">Disabled</span>
              </label>
            </div>
          </div>

          {/* Playground Preview Stage */}
          <div className="p-8 rounded-lg bg-gray-100/70 border border-gray-200 flex flex-col items-center justify-center gap-4 min-h-[140px]">
            <Button
              variant={selectedVariant}
              size={selectedSize}
              isLoading={loading}
              disabled={disabled}
              icon={showIcon ? <SearchIcon /> : undefined}
              onClick={() => alert(`Clicked Ant Design <Button variant="${selectedVariant}" size="${selectedSize}">`)}
            >
              Ant Design Button
            </Button>
            <span className="text-[11px] text-gray-400 font-mono">
              &lt;Button variant="{selectedVariant}" size="{selectedSize}"{loading ? ' isLoading' : ''}{disabled ? ' disabled' : ''}&gt;
            </span>
          </div>
        </section>

      </div>
    </div>
  );
};

export default ButtonDemo;
