import { useState } from 'preact/hooks'
import { api } from '../api.js'
import { usePoll } from '../hooks.js'
import { Toggle, Dot, useToast } from '../ui.jsx'
import { dnsZone } from '../format.js'

// 配置下发动作（人话下拉，对齐后端 add|remove|clear）。
const ACTION_OPTS = [['add', '添加'], ['remove', '移除'], ['clear', '清空']]
const PROTO_OPTS = [['tcp', 'TCP'], ['udp', 'UDP']]
const DACTION_OPTS = [['accept', '放行'], ['drop', '丢弃']]

// 声明式表单清单：每项 = 一张卡片。action=true 走 增删清 语义（清空时隐藏值字段）；
// 否则为直接「设置」（hostname/ipv4）。fields 描述输入控件，build 可定制请求体。
const FORMS = [
  {
    key: 'connector', api: 'cfgConnector', title: '连接器', btn: '下发', action: true,
    desc: '本机主动外联的对端地址（作为客户端拨号接入网络）。',
    fields: [{ name: 'url', label: '地址', ph: 'tcp://203.0.113.7:11010', mono: true }],
  },
  {
    key: 'mapped-listener', api: 'cfgMappedListener', title: '映射监听', btn: '下发', action: true,
    desc: '对外公布的可达监听地址（NAT/端口映射后，供他人回连本机）。',
    fields: [{ name: 'url', label: '地址', ph: 'tcp://203.0.113.7:11010', mono: true }],
  },
  {
    key: 'port-forward', api: 'cfgPortForward', title: '端口转发', btn: '下发', action: true,
    desc: '把本机某端口的流量转发到网络内目标地址。',
    fields: [
      { name: 'protocol', label: '协议', type: 'select', opts: PROTO_OPTS, def: 'tcp' },
      { name: 'bind_addr', label: '本地绑定', ph: '127.0.0.1:8080', mono: true },
      { name: 'dst_addr', label: '目标地址', ph: '10.0.0.5:80', mono: true, optional: true },
    ],
  },
  {
    key: 'route', api: 'cfgRoute', title: '路由', btn: '下发', action: true,
    desc: '声明本机可达的网段，使其经本节点在网络内可路由。',
    fields: [{ name: 'cidr', label: '网段', ph: '10.0.0.0/24', mono: true }],
  },
  {
    key: 'exit-node', api: 'cfgExitNode', title: '出口节点', btn: '下发', action: true,
    desc: '把流量从指定节点出网（全流量出口/默认网关）。',
    fields: [{ name: 'node', label: '节点 IP', ph: '10.0.0.1', mono: true }],
  },
  {
    key: 'relay-serving', api: 'cfgRelayServing', title: '中继服务', btn: '下发', action: true,
    desc: '为其他网络提供中继/打洞协助（按对方管理公钥授权，限时）。',
    fields: [
      { name: 'foreign_root_pk_hex', label: '对方管理公钥', ph: 'hex…', mono: true },
      { name: 'can_relay_data', label: '中继数据', type: 'check' },
      { name: 'can_assist_holepunch', label: '协助打洞', type: 'check' },
      { name: 'ttl_secs', label: '有效期（秒）', type: 'num', def: '3600' },
    ],
  },
  {
    key: 'whitelist', api: 'cfgWhitelist', title: '端口白名单', btn: '应用',
    desc: '仅放行白名单端口的入站连接；勾选「清空」则放行全部。整列替换。',
    fields: [
      { name: 'kind', label: '协议', type: 'select', opts: PROTO_OPTS, def: 'tcp' },
      { name: 'ports', label: '端口', ph: '80,443,8000-8100' },
      { name: 'clear', label: '清空（放行全部）', type: 'check' },
    ],
  },
]

function Sel({ value, opts, onChange }) {
  return (
    <select class="field field-sm" value={value} onChange={(e) => onChange(e.currentTarget.value)}>
      {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  )
}

function initVals(form) {
  const v = {}
  if (form.action) v.action = 'add'
  for (const f of form.fields) {
    v[f.name] = f.type === 'check' ? false : f.def != null ? f.def : ''
  }
  return v
}

function PatchCard({ form }) {
  const toast = useToast()
  const [v, setV] = useState(() => initVals(form))
  const [busy, setBusy] = useState(false)
  const set = (k, val) => setV((s) => ({ ...s, [k]: val }))
  const clearing = form.action && v.action === 'clear'

  const submit = async () => {
    setBusy(true)
    try {
      const body = form.build ? form.build(v) : { ...v }
      // num 字段转数字；可空字段留空时不发送。
      if (!form.build) {
        for (const f of form.fields) {
          if (f.type === 'num') body[f.name] = Number(v[f.name]) || 0
          if (f.optional && (body[f.name] == null || String(body[f.name]).trim() === '')) delete body[f.name]
        }
      }
      await api[form.api](body)
      toast.ok(`${form.title}已下发`)
    } catch (e) {
      toast.err(`${form.title}下发失败：${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="card cfg-card">
      <div class="card-title">{form.title}</div>
      <p class="muted cfg-desc">{form.desc}</p>
      <div class="cfg-row">
        {form.action && <Sel value={v.action} opts={ACTION_OPTS} onChange={(val) => set('action', val)} />}
        {!clearing && form.fields.map((f) =>
          f.type === 'check' ? (
            <Toggle key={f.name} label={f.label} checked={v[f.name]} onChange={(val) => set(f.name, val)} />
          ) : f.type === 'select' ? (
            <label key={f.name} class="cfg-field">
              <span class="cfg-label">{f.label}</span>
              <Sel value={v[f.name]} opts={f.opts} onChange={(val) => set(f.name, val)} />
            </label>
          ) : (
            <label key={f.name} class="cfg-field">
              <span class="cfg-label">{f.label}{f.optional && <small>可空</small>}</span>
              <input
                class={'field field-sm' + (f.mono ? ' mono' : '')}
                type={f.type === 'num' ? 'number' : 'text'}
                value={v[f.name]}
                placeholder={f.ph}
                onInput={(e) => set(f.name, e.currentTarget.value)}
              />
            </label>
          ),
        )}
        <button class="btn btn-primary" disabled={busy} onClick={submit}>{busy ? '下发中…' : form.btn}</button>
      </div>
    </div>
  )
}

// MagicDNS 可热切：开关走 InstanceConfigPatch.accept_dns，网络域走 tld_dns_zone；
// 下发后 daemon 就地重建 TUN NIC 使 DnsRunner 随之拉起/撤下。状态取自 NetworkConfig
// / NodeInfo（TOML），需 daemon 运行。
function DnsCard() {
  const toast = useToast()
  const cfg = usePoll(api.config, [], 8000)
  const node = usePoll(api.node, [], 8000)
  const down = !!cfg.error || !!node.error
  const curEnabled = cfg.data?.enable_magic_dns
  const curZone = dnsZone(node.data?.node_info?.config)
  const myHost = node.data?.node_info?.hostname

  const [enable, setEnable] = useState(null)
  const [zone, setZone] = useState('')
  const [busy, setBusy] = useState(false)
  // 未触碰开关时跟随当前状态；一旦用户改动即以本地值为准。
  const eff = enable == null ? !!curEnabled : enable

  const apply = async () => {
    setBusy(true)
    try {
      await api.cfgDns(eff, zone.trim())
      toast.ok('MagicDNS 已下发')
      setZone('')
    } catch (e) {
      toast.err(`MagicDNS 下发失败：${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="card cfg-card">
      <div class="card-title">MagicDNS</div>
      <p class="muted cfg-desc">用 hostname 访问网络内设备（FQDN = hostname.网络域）。下发后本机 TUN 会短暂重建以生效。</p>
      {down ? (
        <div class="card-degrade"><Dot kind="err" label="daemon 未连接" /><span class="muted">启动 daemon 后可开关 MagicDNS。</span></div>
      ) : (
        <>
          <dl class="kv">
            <dt>当前状态</dt>
            <dd>{curEnabled == null ? '—' : <Dot kind={curEnabled ? 'ok' : 'muted'} label={curEnabled ? '已启用' : '未启用'} />}</dd>
            <dt>网络域</dt><dd class="mono">{curZone || '—'}</dd>
            {curZone && myHost && (<><dt>本机 FQDN</dt><dd class="mono">{myHost}.{curZone}</dd></>)}
          </dl>
          <div class="cfg-row">
            <Toggle label="启用 MagicDNS" checked={eff} onChange={setEnable} />
            <label class="cfg-field">
              <span class="cfg-label">网络域<small>留空保持</small></span>
              <input
                class="field field-sm mono"
                type="text"
                value={zone}
                placeholder={curZone || 'home.pm.'}
                onInput={(e) => setZone(e.currentTarget.value)}
              />
            </label>
            <button class="btn btn-primary" disabled={busy} onClick={apply}>{busy ? '下发中…' : '下发'}</button>
          </div>
        </>
      )}
    </div>
  )
}

// 按用途分区，避免一屏并列十张同质表单。
const SECTIONS = [
  { key: 'access', title: '接入与监听', desc: '本机如何接入网络，以及对外暴露的端口。' },
  { key: 'routing', title: '路由与网段', desc: '经本机可达的网段、出口节点与中继服务。' },
]
const SEC_OF = {
  connector: 'access', 'mapped-listener': 'access', 'port-forward': 'access', whitelist: 'access',
  route: 'routing', 'exit-node': 'routing', 'relay-serving': 'routing',
}

export function Config() {
  return (
    <>
      <div class="card card-degrade cfg-note">
        <span class="muted">以下配置仅作用于<strong>本机节点</strong>，经本机 daemon 热重载下发（<strong>需 daemon 运行中</strong>）；下发后在「设备 / 诊断」查看生效结果。网络级设置（成员 IP、子网路由概览）见「网络」页。</span>
      </div>
      {SECTIONS.map((s) => (
        <section key={s.key} class="cfg-section">
          <div class="cfg-section-head">
            <h2>{s.title}</h2>
            <span class="muted">{s.desc}</span>
          </div>
          {FORMS.filter((f) => SEC_OF[f.key] === s.key).map((f) => <PatchCard key={f.key} form={f} />)}
        </section>
      ))}
      <section class="cfg-section">
        <div class="cfg-section-head">
          <h2>名称解析</h2>
          <span class="muted">用 hostname 访问网络内设备（MagicDNS）。</span>
        </div>
        <DnsCard />
      </section>
    </>
  )
}
