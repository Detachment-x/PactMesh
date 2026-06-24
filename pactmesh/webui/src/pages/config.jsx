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
    key: 'proxy-network', api: 'cfgProxyNetwork', title: '代理网段', btn: '下发', action: true,
    desc: '代理一段子网进入网络，可选映射为另一网段以避免冲突。',
    fields: [
      { name: 'cidr', label: '网段', ph: '192.168.1.0/24', mono: true },
      { name: 'mapped_cidr', label: '映射网段', ph: '10.99.1.0/24', mono: true, optional: true },
    ],
  },
  {
    key: 'exit-node', api: 'cfgExitNode', title: '出口节点', btn: '下发', action: true,
    desc: '把流量从指定节点出网（全流量出口/默认网关）。',
    fields: [{ name: 'node', label: '节点 IP', ph: '10.0.0.1', mono: true }],
  },
  {
    key: 'relay-serving', api: 'cfgRelayServing', title: '中继服务', btn: '下发', action: true,
    desc: '为其他信任域提供中继/打洞协助（按对方 root 公钥授权，限时）。',
    fields: [
      { name: 'foreign_root_pk_hex', label: '对方 root 公钥', ph: 'hex…', mono: true },
      { name: 'can_relay_data', label: '中继数据', type: 'check' },
      { name: 'can_assist_holepunch', label: '协助打洞', type: 'check' },
      { name: 'ttl_secs', label: '有效期（秒）', type: 'num', def: '3600' },
    ],
  },
  {
    key: 'hostname', api: 'cfgHostname', title: '本机主机名', btn: '设置',
    desc: '本机在网络内显示的主机名（留空清除）。',
    fields: [{ name: 'hostname', label: '主机名', ph: 'my-laptop' }],
    build: (v) => v.hostname,
  },
  {
    key: 'ipv4', api: 'cfgIpv4', title: '虚拟 IP', btn: '设置',
    desc: '本机在网络内的虚拟 IPv4 地址（CIDR 形式）。',
    fields: [{ name: 'ipv4', label: '地址', ph: '10.0.0.2/24', mono: true }],
    build: (v) => v.ipv4,
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

// MagicDNS 只读：启用状态取自 NetworkConfig.enable_magic_dns；网络域取自 NodeInfo.config（TOML）。
// 二者均需 daemon 运行；启用/停用不可经控制器热切（InstanceConfigPatch 无 DNS 字段），故仅展示。
function DnsCard() {
  const cfg = usePoll(api.config, [], 8000)
  const node = usePoll(api.node, [], 8000)
  const down = !!cfg.error || !!node.error
  const enabled = cfg.data?.enable_magic_dns
  const zone = dnsZone(node.data?.node_info?.config)
  const myHost = node.data?.node_info?.hostname

  return (
    <div class="card cfg-card">
      <div class="card-title">MagicDNS<span class="badge-role role-cred-soft">只读</span></div>
      <p class="muted cfg-desc">用主机名访问网络内设备（FQDN = 主机名.网络域）。此处仅展示状态；启用/停用需在启动 daemon 时配置。</p>
      {down ? (
        <div class="card-degrade"><Dot kind="err" label="daemon 未连接" /><span class="muted">启动 daemon 后显示 MagicDNS 状态。</span></div>
      ) : (
        <dl class="kv">
          <dt>状态</dt>
          <dd>{enabled == null ? '—' : <Dot kind={enabled ? 'ok' : 'muted'} label={enabled ? '已启用' : '未启用'} />}</dd>
          <dt>网络域</dt><dd class="mono">{zone || '—'}</dd>
          {zone && myHost && (<><dt>本机 FQDN</dt><dd class="mono">{myHost}.{zone}</dd></>)}
        </dl>
      )}
      <p class="muted cfg-desc">启用方法：daemon 启动时设置 <code>accept_dns = true</code> 与 <code>tld_dns_zone</code>（或建实例时开启 MagicDNS）。</p>
    </div>
  )
}

export function Config() {
  return (
    <>
      <div class="card card-degrade cfg-note">
        <span class="muted">配置经本机 daemon 热重载下发，<strong>需 daemon 运行中</strong>；下发后在「设备 / 诊断」查看生效结果。</span>
      </div>
      {FORMS.map((f) => <PatchCard key={f.key} form={f} />)}
      <DnsCard />
    </>
  )
}
