// Utility functions for safe rendering of user data
// React automatically escapes JSX content, but these utilities provide additional safety

/**
 * Safely renders text content by ensuring it's properly escaped
 * React's JSX automatically escapes content, but this utility ensures consistency
 */
export const SafeText = ({ children, ...props }: { children: React.ReactNode } & React.HTMLAttributes<HTMLSpanElement>) => {
  return <span {...props}>{children}</span>;
};

/**
 * Safely renders JSON data for display
 * Ensures the data is properly stringified and escaped
 */
export const SafeJsonDisplay = ({
  data,
  indent = 2,
  ...props
}: {
  data: unknown;
  indent?: number;
} & React.HTMLAttributes<HTMLPreElement>) => {
  const safeJson = JSON.stringify(data, null, indent)
    .replace(/</g, '\\u003c')  // Escape < to prevent HTML injection
    .replace(/>/g, '\\u003e')  // Escape > to prevent HTML injection
    .replace(/&/g, '\\u0026'); // Escape & to prevent HTML injection

  return <pre {...props}>{safeJson}</pre>;
};

/**
 * Safely renders user input that might contain special characters
 * Strips or escapes potentially dangerous characters
 */
export const SafeUserInput = ({ text, ...props }: { text: string } & React.HTMLAttributes<HTMLSpanElement>) => {
  // Remove or escape control characters and potentially dangerous Unicode
  // Using filter method to avoid ESLint control-regex warning
  const safeText = Array.from(text)
    .filter(char => {
      const code = char.charCodeAt(0);
      // Remove ASCII control characters (0x00-0x1F, 0x7F-0x9F)
      return !((code >= 0x00 && code <= 0x1F) || (code >= 0x7F && code <= 0x9F));
    })
    .join('')
    .replace(/[<>'"&]/g, (char) => {
      switch (char) {
        case '<': return '\\u003c';
        case '>': return '\\u003e';
        case '"': return '\\u0022';
        case "'": return '\\u0027';
        case '&': return '\\u0026';
        default: return char;
      }
    });

  return <span {...props}>{safeText}</span>;
};