/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface MetadataUploadProps {
  /** Current uploaded file name, if any (drives the "has-file" state). */
  fileName?: string;
  /** Called with the file's name and its text content once read. */
  onLoaded: (fileName: string, xml: string) => void;
  /** Called when the user clears the uploaded file. */
  onClear: () => void;
}

/** SAML IdP-metadata XML uploader — styled dropzone with click + drag-and-drop. */
export function MetadataUpload({ fileName, onLoaded, onClear }: MetadataUploadProps) {
  const inputRef = React.useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = React.useState(false);

  const read = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => onLoaded(file.name, String(reader.result ?? ""));
    reader.readAsText(file);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) read(file);
  };

  if (fileName) {
    return (
      <div className="hx-dropzone hx-dropzone--has-file">
        <FileIcon />
        <span className="hx-dropzone__filename">
          {fileName}
        </span>
        <button type="button" className="hx-btn hx-btn--ghost hx-dropzone__remove" onClick={onClear}>
          Remove
        </button>
      </div>
    );
  }

  return (
    <div
      className={`hx-dropzone${dragging ? " hx-dropzone--drag" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
    >
      <UploadIcon />
      <div className="hx-dropzone__text">
        <span className="hx-dropzone__title">Upload metadata XML</span>
        <span className="hx-dropzone__hint">Drag &amp; drop or browse — .xml</span>
      </div>
      <button type="button" className="hx-btn hx-btn--ghost hx-dropzone__browse" onClick={() => inputRef.current?.click()}>
        Browse…
      </button>
      <input
        ref={inputRef}
        type="file"
        accept=".xml,application/xml,text/xml"
        className="hx-visually-hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) read(file);
          e.target.value = ""; // allow re-selecting the same file
        }}
      />
    </div>
  );
}

function UploadIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true" className="hx-dropzone__icon">
      <path d="M12 16V4m0 0L8 8m4-4l4 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function FileIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true" className="hx-dropzone__icon">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M14 2v6h6" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}
