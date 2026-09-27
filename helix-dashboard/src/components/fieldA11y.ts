/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

/**
 * What a FormField tells the control inside it: the ids of its hint and error (for aria-describedby and
 * aria-errormessage) and whether it is invalid. Input, Textarea and Select read it, so every form in the console gets
 * the links without passing props. A control's own aria-* props win.
 */
export interface FieldA11y {
  describedBy?: string;
  errorId?: string;
  invalid: boolean;
}
export const FieldContext = React.createContext<FieldA11y | null>(null);

/** The aria-* attributes a control inside a FormField should carry (merged with its own). */
export function useFieldA11y(own: { "aria-describedby"?: string; "aria-invalid"?: React.AriaAttributes["aria-invalid"]; "aria-errormessage"?: string }) {
  const field = React.useContext(FieldContext);
  if (!field) return {};
  const describedBy = [own["aria-describedby"], field.describedBy].filter(Boolean).join(" ") || undefined;
  return {
    "aria-describedby": describedBy,
    "aria-invalid": own["aria-invalid"] ?? (field.invalid ? true : undefined),
    "aria-errormessage": own["aria-errormessage"] ?? (field.invalid ? field.errorId : undefined),
  };
}

