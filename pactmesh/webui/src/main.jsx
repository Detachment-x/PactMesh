import { render } from 'preact'
import './styles.css'
import { App } from './app.jsx'
import { ToastProvider } from './ui.jsx'
import { AppProvider } from './store.jsx'

render(
  <ToastProvider>
    <AppProvider>
      <App />
    </AppProvider>
  </ToastProvider>,
  document.getElementById('app'),
)
