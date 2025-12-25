import { useEffect, useRef, useState } from 'react';
import { basicSetup, EditorView } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { yaml } from '@codemirror/lang-yaml';
import { oneDark } from '@codemirror/theme-one-dark';
import { Box, Alert } from '@mui/material';

interface YamlEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  minHeight?: string;
  error?: boolean;
}

/**
 * YAML Editor Component
 *
 * A syntax-highlighted YAML editor built on CodeMirror 6.
 *
 * Features:
 * - YAML syntax highlighting
 * - Dark theme (oneDark)
 * - Real-time validation support via error prop
 * - Readonly mode support
 * - Customizable min height
 *
 * Accessibility:
 * - Keyboard navigation fully supported by CodeMirror
 * - Focus states are visually indicated
 * - Error states use color + border style for distinction
 *
 * @param value - Current YAML content
 * @param onChange - Callback fired when content changes
 * @param placeholder - Placeholder text (optional)
 * @param readOnly - Whether editor is read-only
 * @param minHeight - Minimum editor height (default: 80px)
 * @param error - Whether to show error styling
 */
export function YamlEditor({
  value,
  onChange,
  readOnly = false,
  minHeight = '80px',
  error = false
}: YamlEditorProps) {
  const editorRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);

  useEffect(() => {
    if (!editorRef.current) return;

    try {
      const state = EditorState.create({
        doc: String(value ?? ''),
        extensions: [
          basicSetup,
          yaml(),
          oneDark,
          EditorView.updateListener.of((update) => {
            if (update.docChanged && !readOnly) {
              onChange(update.state.doc.toString());
            }
          }),
          EditorView.editable.of(!readOnly),
          EditorView.theme({
            '&': {
              minHeight: minHeight,
              fontSize: '13px',
              fontFamily: 'Consolas, Monaco, "Courier New", monospace'
            },
            '.cm-content': {
              padding: '8px',
              caretColor: '#4CAF50'
            },
            '.cm-scroller': {
              overflow: 'auto',
              fontFamily: 'Consolas, Monaco, "Courier New", monospace'
            }
          })
        ]
      });

      const view = new EditorView({
        state,
        parent: editorRef.current
      });

      viewRef.current = view;
      setEditorError(null);

      return () => {
        try {
          view.destroy();
        } catch (err) {
          console.error('Failed to destroy editor:', err);
        }
      };
    } catch (err) {
      setEditorError(`Failed to initialize YAML editor: ${(err as Error).message}`);
      return;
    }
  }, [minHeight, onChange, readOnly, value]);

  useEffect(() => {
    if (viewRef.current) {
      try {
        const currentValue = viewRef.current.state.doc.toString();
        const newValue = String(value ?? '');
        if (currentValue !== newValue) {
          viewRef.current.dispatch({
            changes: { from: 0, to: currentValue.length, insert: newValue }
          });
        }
      } catch (err) {
        console.error('Failed to update editor content:', err);
      }
    }
  }, [value]);

  // Render error state if editor initialization failed
  if (editorError) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        {editorError}
      </Alert>
    );
  }

  return (
    <Box
      ref={editorRef}
      sx={{
        border: error ? '2px solid #f44336' : '1px solid rgba(255, 255, 255, 0.23)',
        borderRadius: '4px',
        overflow: 'hidden',
        '&:hover': {
          borderColor: error ? '#f44336' : 'rgba(255, 255, 255, 0.87)'
        },
        '&:focus-within': {
          borderColor: error ? '#f44336' : 'primary.main',
          borderWidth: '2px'
        }
      }}
      role="group"
      aria-label="YAML editor"
      aria-invalid={error}
    />
  );
}
