# NodeAPI编译

本项目基于原生`napi`和`node-addon-api`库实现`node.js`的第三方库

## 构建

```Shell
npm install
npm run build
```

结果存在于`./build/Release/dog_torch_napi.node`

## 测试

```Shell
npm run test
```

可以从`test.js`中查看API的使用方法和测试API可用性
