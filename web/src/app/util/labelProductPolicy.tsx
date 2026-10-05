import React from 'react'

// Labels are outside MS OnCall product scope. Public configuration, including
// missing or historical configuration, cannot enable the retained upstream UI.
export function labelsDisabled(): boolean {
  return true
}

export function withoutLabelUI<P extends object>(
  Content: React.ComponentType<P>,
): React.ComponentType<P> {
  return function LabelProductBoundary(props: P): React.JSX.Element | null {
    if (labelsDisabled()) return null
    return <Content {...props} />
  }
}
