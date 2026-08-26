# DSH 构件晋级证据

这是 DeepSeek Harness 供应链的离线、确定性证据层。它核验同一个显式 artifact digest 是否按声明的 build → staging → production 阶段顺序递进，并在每一阶段保持环境绑定、前序部署回执和必需关卡证据完整。

它不执行部署、不访问 registry、不授予审批、不验证运行健康，也不修改环境；同时不认证回执或验证 provenance 签名。`promoted` 只表示输入的纯哈希记录内部完整、有序并符合策略。

这与现有层互补：release-proof 对账下载端，attestation-proof 验签，reproducible-build-proof 验证独立重建收敛，build-hermeticity-proof 核验单次构建的外部影响闭包，output-custody-proof 核验 DSH 工具结果的投影与持久化。`dsh-evidence-arena` 的 promotion 是把竞赛候选工作树写回代码仓；本插件不写候选或仓库。

阶段必须无缺失且顺序一致；artifact、环境与前序部署回执必须连续。关卡必须绑定相同 artifact、先于晋级发生并满足不同 authority 数量。输入只接受工作区内非符号链接 JSON，输出只写显式 `artifactDir` 的内容寻址报告并回读校验。
