import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

// 产物为单个内联 index.html，emit 到后端 include_str! 目标目录。
// 运行期零 Node/零外部依赖；Node 仅开发/构建期需要。
export default defineConfig({
  base: './',
  plugins: [preact(), viteSingleFile()],
  build: {
    outDir: '../src/controller/assets/dist',
    emptyOutDir: true,
    assetsInlineLimit: 100000000,
    cssCodeSplit: false,
  },
})
