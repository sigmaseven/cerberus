import { useEffect, useRef } from 'react';
import { basicSetup, EditorView } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { json } from '@codemirror/lang-json';
import { oneDark } from '@codemirror/theme-one-dark';
import { Box } from '@mui/material';

interface JsonEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  minHeight?: string;
  error?: boolean;
}

export function JsonEditor({
  value,
  onChange,
  readOnly = false,
  minHeight = '80px',
  error = false
}: JsonEditorProps) {
  const editorRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);

  useEffect(() => {
    if (!editorRef.current) return;

    const state = EditorState.create({
      doc: String(value || ''),
      extensions: [
        basicSetup,
        json(),
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

    return () => {
      view.destroy();
    };
  }, [minHeight, onChange, readOnly, value]);

  useEffect(() => {
    if (viewRef.current) {
      const currentValue = viewRef.current.state.doc.toString();
      const newValue = String(value || '');
      if (currentValue !== newValue) {
        viewRef.current.dispatch({
          changes: { from: 0, to: currentValue.length, insert: newValue }
        });
      }
    }
  }, [value]);

  return (
    <Box
      ref={editorRef}
      sx={{
        border: error ? '1px solid #f44336' : '1px solid rgba(255, 255, 255, 0.23)',
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
    />
  );
}
