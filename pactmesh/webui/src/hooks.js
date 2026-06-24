import { useState, useEffect, useRef, useCallback } from 'preact/hooks'

// 轮询数据层：拉取 + 定时刷新（页面隐藏时暂停），返回 diff 友好的状态。
// fn 必须稳定（用 useCallback 包裹）或经 deps 重建。
export function usePoll(fn, deps = [], intervalMs = 2000) {
  const [state, setState] = useState({ data: null, error: null, loading: true })
  const fnRef = useRef(fn)
  fnRef.current = fn
  const alive = useRef(true)

  const run = useCallback(async (quiet) => {
    if (!quiet) setState((s) => ({ ...s, loading: true }))
    try {
      const data = await fnRef.current()
      if (alive.current) setState({ data, error: null, loading: false })
    } catch (error) {
      if (alive.current) setState((s) => ({ ...s, error, loading: false }))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    alive.current = true
    run(false)
    if (!intervalMs) return () => { alive.current = false }
    const id = setInterval(() => {
      if (!document.hidden) run(true)
    }, intervalMs)
    return () => {
      alive.current = false
      clearInterval(id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return { ...state, refresh: () => run(true) }
}

// 一次性异步动作：手动触发，返回 {run, pending, error}。
export function useAction(fn) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)
  const run = useCallback(
    async (...args) => {
      setPending(true)
      setError(null)
      try {
        return await fn(...args)
      } catch (e) {
        setError(e)
        throw e
      } finally {
        setPending(false)
      }
    },
    [fn],
  )
  return { run, pending, error }
}
