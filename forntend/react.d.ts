// Type definitions for React and JSX
declare namespace React {
  type ReactNode =
    | ReactElement
    | string
    | number
    | boolean
    | null
    | undefined
    | ReactNodeArray
    | Iterable<ReactNode>;

  interface ReactNodeArray extends Array<ReactNode> {}

  interface ReactElement<P = any, T extends string | JSXElementConstructor<any> = string | JSXElementConstructor<any>> {
    type: T;
    props: P;
    key: string | number | null;
  }

  type JSXElementConstructor<P> =
    | ((props: P) => ReactElement<any, any> | null)
    | (new (props: P) => Component<any, any>);

  interface Component<P = {}, S = {}> {}

  interface FunctionComponent<P = {}> {
    (props: P, context?: any): ReactElement<any, any> | null;
    propTypes?: any;
    contextTypes?: any;
    defaultProps?: Partial<P>;
    displayName?: string;
  }

  type FC<P = {}> = FunctionComponent<P>;

  interface RefObject<T> {
    readonly current: T | null;
  }

  type RefCallback<T> = (instance: T | null) => void;
  type Ref<T> = RefCallback<T> | RefObject<T> | null;
  type ForwardedRef<T> = ((instance: T | null) => void) | React.MutableRefObject<T | null> | null;

  interface MutableRefObject<T> {
    current: T;
  }

  interface HTMLAttributes<T> extends AriaAttributes, DOMAttributes<T> {
    className?: string;
    id?: string;
    style?: any;
    title?: string;
    role?: string;
    tabIndex?: number;
    hidden?: boolean;
    [key: string]: any;
  }

  interface ButtonHTMLAttributes<T> extends HTMLAttributes<T> {
    autoFocus?: boolean;
    disabled?: boolean;
    form?: string;
    formAction?: string;
    name?: string;
    type?: 'submit' | 'reset' | 'button';
    value?: string | string[] | number;
    onClick?: (event: any) => void;
  }

  interface AriaAttributes {
    'aria-busy'?: boolean | 'true' | 'false';
    'aria-hidden'?: boolean | 'true' | 'false';
    'aria-expanded'?: boolean | 'true' | 'false';
    [key: string]: any;
  }

  interface DOMAttributes<T> {
    children?: ReactNode;
    onClick?: (event: any) => void;
    onChange?: (event: any) => void;
    onKeyDown?: (event: any) => void;
    [key: string]: any;
  }

  function useState<T>(initialState: T | (() => T)): [T, (value: T | ((prevState: T) => T)) => void];
  function forwardRef<T, P = {}>(
    render: (props: P, ref: ForwardedRef<T>) => ReactNode
  ): {
    (props: P & { ref?: Ref<T> }): ReactElement | null;
    displayName?: string;
  };
  function createElement(type: any, props?: any, ...children: any[]): ReactElement;
}

declare module 'react' {
  export = React;
}

declare module 'react/jsx-runtime' {
  export const jsx: any;
  export const jsxs: any;
  export const Fragment: any;
}

declare global {
  namespace JSX {
    interface Element extends React.ReactElement<any, any> {}
    interface ElementClass extends React.Component<any> {}
    interface IntrinsicElements {
      [elemName: string]: any;
    }
  }
}
