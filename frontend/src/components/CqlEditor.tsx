import { useEffect, useRef } from 'react';
import { basicSetup, EditorView } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { oneDark } from '@codemirror/theme-one-dark';
import { Box } from '@mui/material';
import { autocompletion } from '@codemirror/autocomplete';
import { cql } from './cql-language';
import { cqlAutocomplete } from './cql-autocomplete';

interface CqlEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  minHeight?: string;
}

export function CqlEditor({ value, onChange, readOnly = false, minHeight = '150px' }: CqlEditorProps) {
  const editorRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);

  useEffect(() => {
    if (!editorRef.current) return;

    const state = EditorState.create({
      doc: String(value || ''),
      extensions: [
        basicSetup,
        cql(),
        oneDark,
        autocompletion({
          override: [cqlAutocomplete],
          activateOnTyping: true,
          maxRenderedOptions: 20,
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged && !readOnly) {
            onChange(update.state.doc.toString());
          }
        }),
        EditorView.editable.of(!readOnly),
        EditorView.lineWrapping,
        EditorView.theme({
          '&': {
            minHeight: minHeight,
            fontSize: '14px',
            fontFamily: 'Consolas, Monaco, "Courier New", monospace'
          },
          '.cm-content': {
            padding: '10px',
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
        border: '1px solid rgba(255, 255, 255, 0.23)',
        borderRadius: '4px',
        overflow: 'hidden',
        '&:hover': {
          borderColor: 'rgba(255, 255, 255, 0.87)'
        },
        '&:focus-within': {
          borderColor: 'primary.main',
          borderWidth: '2px'
        }
      }}
    />
  );
}
