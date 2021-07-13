# tp5-user-rbac
>本扩展包是基于tp5-rbac之上重新编译开发，主要是针对osocms系统的后台对应的开发扩展，对所有的方法进行了重写，后续会在此功能上继续更新；
>在开发CMS的过程中发现用户和管理员必须做权限的区分，这个很好的适应了后台管理员的开发，这是USER的RBAC的版本，欢迎大家的使用。
## 安装方法
先安装composer如果不知道怎么安装使用composer请自行百度。
打开命令行工具切换到你的tp5项目根目录

```
composer require dgosc/tp5-user-rbac
```  

如果该方法报错请按照以下方式操作：

1. 打开项目根目录下的composer.json
2. 在require中添加"DGOSC/tp5-user-rbac": "dev-master"
3. 运行composer update

添加后composer.json应该有这样的部分：

```
    "require": {
        "php": ">=5.4.0",
        "topthink/framework": "^5.0",
        "DGOSC/tp5-admin-rbac": "dev-master"
    },