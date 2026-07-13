import { createContext } from 'preact'
import { useContext, useState, useCallback, useRef, useEffect } from 'preact/hooks'

// ---------------- Toast ----------------
const ToastCtx = createContext(null)
let toastSeq = 0

export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const remove = useCallback((id) => setItems((l) => l.filter((t) => t.id !== id)), [])
  const push = useCallback(
    (message, kind = 'ok', ttl = 3200) => {
      const id = ++toastSeq
      setItems((l) => [...l, { id, message, kind }])
      if (ttl) setTimeout(() => remove(id), ttl)
      return id
    },
    [remove],
  )
  const toast = {
    ok: (m) => push(m, 'ok'),
    err: (m) => push(m, 'err', 5000),
    info: (m) => push(m, 'info'),
  }
  return (
    <ToastCtx.Provider value={toast}>
      {children}
      <div class="toast-stack">
        {items.map((t) => (
          <div key={t.id} class={`toast toast-${t.kind}`} onClick={() => remove(t.id)}>
            {t.message}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export const useToast = () => useContext(ToastCtx)

// ---------------- 加载骨架 ----------------
export function Skeleton({ rows = 3 }) {
  return (
    <div class="skeleton">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} class="skeleton-row" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  )
}

// ---------------- 空状态 ----------------
export function EmptyState({ icon = '✦', title, hint, action }) {
  return (
    <div class="empty-state">
      <div class="empty-icon">{icon}</div>
      <div class="empty-title">{title}</div>
      {hint && <div class="empty-hint">{hint}</div>}
      {action && <div class="empty-action">{action}</div>}
    </div>
  )
}

// ---------------- 错误占位 ----------------
export function ErrorState({ error, onRetry }) {
  return (
    <div class="empty-state">
      <div class="empty-icon" style={{ color: 'var(--err)' }}>!</div>
      <div class="empty-title">加载失败</div>
      <div class="empty-hint">{String(error?.message || error)}</div>
      {onRetry && (
        <div class="empty-action">
          <button class="btn" onClick={onRetry}>重试</button>
        </div>
      )}
    </div>
  )
}

// ---------------- 模态 ----------------
export function Modal({ title, onClose, children, footer, width = 420 }) {
  // onClose 每次渲染都是新函数，若入依赖数组则 effect 每渲染重跑；重跑时把焦点抢回弹窗容器，
  // 会导致口令输入框每敲一个字符就掉焦。故经 ref 取最新 onClose、依赖置空，且不抢焦点。
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onCloseRef.current?.()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])
  return (
    <div class="modal-backdrop" onClick={onClose}>
      <div class="modal" style={{ width: `${width}px` }} onClick={(e) => e.stopPropagation()}>
        <div class="modal-head">
          <span>{title}</span>
          <button class="modal-x" onClick={onClose} aria-label="关闭">✕</button>
        </div>
        <div class="modal-body">{children}</div>
        {footer && <div class="modal-foot">{footer}</div>}
      </div>
    </div>
  )
}

// ---------------- 抽屉（右侧滑入，承载成员详情/编辑） ----------------
export function Drawer({ title, subtitle, onClose, children, footer }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose?.()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div class="drawer-backdrop" onClick={onClose}>
      <aside class="drawer" onClick={(e) => e.stopPropagation()}>
        <div class="drawer-head">
          <div class="drawer-titles">
            <div class="drawer-title">{title}</div>
            {subtitle && <div class="drawer-sub">{subtitle}</div>}
          </div>
          <button class="modal-x" onClick={onClose} aria-label="关闭">✕</button>
        </div>
        <div class="drawer-body">{children}</div>
        {footer && <div class="drawer-foot">{footer}</div>}
      </aside>
    </div>
  )
}

// ---------------- 开关 ----------------
export function Toggle({ checked, onChange, label, hint, disabled }) {
  return (
    <label class={'toggle-row' + (disabled ? ' disabled' : '')}>
      <span class="toggle-text">
        {label}
        {hint && <small>{hint}</small>}
      </span>
      <span
        class={'switch' + (checked ? ' on' : '')}
        onClick={() => !disabled && onChange(!checked)}
        role="switch"
        aria-checked={checked}
      >
        <span class="knob" />
      </span>
    </label>
  )
}

// ---------------- 短 ID + 复制 ----------------
export function CopyId({ value, chars = 10 }) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span class="muted">—</span>
  const short = value.length > chars ? value.slice(0, chars) + '…' : value
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard 不可用时静默 */
    }
  }
  return (
    <span class="copy-id" title={value} onClick={copy}>
      <code>{short}</code>
      <span class="copy-icon">{copied ? '✓' : '⧉'}</span>
    </span>
  )
}

// ---------------- 状态圆点 ----------------
export function Dot({ kind = 'muted', label }) {
  return (
    <span class="dot-badge">
      <span class={`dot dot-${kind}`} />
      {label}
    </span>
  )
}

// ---------------- 行内可编辑单元格（展示即编辑） ----------------
// 显示态点击进入输入态；Enter/失焦提交、Esc 取消。onCommit(v) 返回 false 则保持编辑
// （如未解锁被取消、提交失败）。空串允许（由 onCommit 自行处理清除语义）。
export function InlineEdit({ value, placeholder = '—', mono, disabled, title = '点击编辑', onCommit, render }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const busyRef = useRef(false)
  const inputRef = useRef(null)
  useEffect(() => { if (editing) inputRef.current?.focus() }, [editing])

  const shown = render
    ? render(value)
    : value
      ? <span class={mono ? 'mono' : ''}>{value}</span>
      : <span class="muted">{placeholder}</span>

  if (disabled) return <span class="inline-ro">{shown}</span>
  if (!editing) {
    return (
      <button type="button" class="inline-edit" title={title} onClick={() => { setDraft(value ?? ''); setEditing(true) }}>
        {shown}
        <span class="inline-pen" aria-hidden="true">✎</span>
      </button>
    )
  }
  const finish = () => { busyRef.current = false; setBusy(false); setEditing(false) }
  const commit = async () => {
    if (busyRef.current) return
    const v = draft.trim()
    if (v === (value ?? '').trim()) { finish(); return }
    busyRef.current = true
    setBusy(true)
    let ok
    try { ok = await onCommit(v) } catch { ok = false }
    if (ok === false) { busyRef.current = false; setBusy(false); inputRef.current?.focus() }
    else finish()
  }
  return (
    <span class="inline-edit-box">
      <input
        ref={inputRef}
        class={'field field-sm' + (mono ? ' mono' : '')}
        value={draft}
        disabled={busy}
        placeholder={placeholder}
        onInput={(e) => setDraft(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); finish() }
        }}
        onBlur={commit}
      />
    </span>
  )
}
