import json
import time
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import shutil


# ==================== 日志记录模块 ====================
class Logger:
    """系统日志记录器"""

    def __init__(self, log_file='system.log'):
        self.log_file = log_file

    def log(self, level: str, operation: str, user: str, details: str = ''):
        """记录日志"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] [User: {user}] {operation}"
        if details:
            log_entry += f" - {details}"

        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')

    def info(self, operation: str, user: str, details: str = ''):
        self.log('INFO', operation, user, details)

    def warning(self, operation: str, user: str, details: str = ''):
        self.log('WARNING', operation, user, details)

    def error(self, operation: str, user: str, details: str = ''):
        self.log('ERROR', operation, user, details)

    def view_logs(self, lines: int = 50):
        """查看最近的日志"""
        if not os.path.exists(self.log_file):
            print("暂无日志记录")
            return

        with open(self.log_file, 'r', encoding='utf-8') as f:
            all_logs = f.readlines()

        print(f"\n{'=' * 80}")
        print(f"最近 {min(lines, len(all_logs))} 条日志记录")
        print('=' * 80)
        for log in all_logs[-lines:]:
            print(log.strip())

    def clear_logs(self):
        """清空日志"""
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
            print("日志已清空")


# ==================== 用户管理模块 ====================
class User:
    """用户类"""

    def __init__(self, username: str, password: str, role: str = 'normal'):
        self.username = username
        self.password_hash = self._hash_password(password)
        self.role = role  # 'normal' 或 'super'
        self.is_locked = False
        self.lock_until = None
        self.failed_attempts = 0

    @staticmethod
    def _hash_password(password: str) -> str:
        """密码哈希"""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def validate_password_strength(password: str) -> tuple:
        """验证密码强度"""
        if len(password) < 8:
            return False, "密码长度不能少于8位"

        if not re.search(r'[a-z]', password):
            return False, "密码必须包含小写字母"

        if not re.search(r'[A-Z]', password):
            return False, "密码必须包含大写字母"

        if not re.search(r'\d', password):
            return False, "密码必须包含数字"

        return True, "密码强度符合要求"

    def verify_password(self, password: str) -> bool:
        """验证密码"""
        return self.password_hash == self._hash_password(password)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'username': self.username,
            'password_hash': self.password_hash,
            'role': self.role,
            'is_locked': self.is_locked,
            'lock_until': self.lock_until.isoformat() if self.lock_until else None,
            'failed_attempts': self.failed_attempts
        }

    @classmethod
    def from_dict(cls, data: dict):
        """从字典创建用户"""
        user = cls.__new__(cls)
        user.username = data['username']
        user.password_hash = data['password_hash']
        user.role = data['role']
        user.is_locked = data.get('is_locked', False)
        lock_until_str = data.get('lock_until')
        user.lock_until = datetime.fromisoformat(lock_until_str) if lock_until_str else None
        user.failed_attempts = data.get('failed_attempts', 0)
        return user


class AuthManager:
    """认证管理器"""

    def __init__(self, logger: Logger):
        self.users: Dict[str, User] = {}
        self.current_user: Optional[User] = None
        self.logger = logger
        self._load_users()

    def _load_users(self):
        """加载用户数据"""
        if os.path.exists('users.json'):
            with open('users.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                for username, user_data in data.items():
                    self.users[username] = User.from_dict(user_data)
        else:
            # 创建默认超级管理员
            self.register('Admin123', 'Admin@123', 'super')
            self.register('User123', 'User@123', 'normal')

    def _save_users(self):
        """保存用户数据"""
        data = {username: user.to_dict() for username, user in self.users.items()}
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def register(self, username: str, password: str, role: str = 'normal') -> bool:
        """注册新用户"""
        if username in self.users:
            return False

        valid, msg = User.validate_password_strength(password)
        if not valid:
            print(f"密码强度不符合要求: {msg}")
            return False

        self.users[username] = User(username, password, role)
        self._save_users()
        return True

    def login(self, username: str, password: str) -> bool:
        """用户登录"""
        if username not in self.users:
            self.logger.warning('登录失败', username, '用户不存在')
            print("用户名或密码错误")
            return False

        user = self.users[username]

        # 检查账号是否被锁定
        if user.is_locked:
            if user.lock_until and datetime.now() < user.lock_until:
                remaining = (user.lock_until - datetime.now()).seconds
                self.logger.warning('登录失败', username, f'账号已锁定，剩余{remaining}秒')
                print(f"账号已被锁定，请在 {remaining} 秒后重试")
                return False
            else:
                # 解锁账号
                user.is_locked = False
                user.lock_until = None
                user.failed_attempts = 0
                self._save_users()

        # 验证密码
        if user.verify_password(password):
            user.failed_attempts = 0
            self.current_user = user
            self._save_users()
            self.logger.info('登录成功', username, f'角色: {user.role}')
            print(f"\n欢迎, {username}! (权限: {'超级管理员' if user.role == 'super' else '普通管理员'})")
            return True
        else:
            user.failed_attempts += 1
            self.logger.warning('登录失败', username, f'密码错误，第{user.failed_attempts}次尝试')

            if user.failed_attempts >= 3:
                user.is_locked = True
                user.lock_until = datetime.now() + timedelta(seconds=30)
                self._save_users()
                self.logger.error('账号锁定', username, '连续3次密码错误')
                print("连续3次输入错误密码，账号已被锁定30秒")
            else:
                print(f"用户名或密码错误 (剩余尝试次数: {3 - user.failed_attempts})")

            return False

    def logout(self):
        """退出登录"""
        if self.current_user:
            self.logger.info('退出登录', self.current_user.username)
            self.current_user = None

    def check_permission(self, required_role: str = 'normal') -> bool:
        """检查权限"""
        if not self.current_user:
            return False

        if required_role == 'super':
            return self.current_user.role == 'super'

        return True


# ==================== 商品管理模块 ====================
class Product:
    """商品类"""

    def __init__(self, product_id: str, name: str, category: str, price: float, stock: int):
        self.product_id = product_id
        self.name = name
        self.category = category
        self.price = price
        self.stock = stock

    @property
    def total_value(self) -> float:
        """商品总价值"""
        return self.price * self.stock

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'product_id': self.product_id,
            'name': self.name,
            'category': self.category,
            'price': self.price,
            'stock': self.stock
        }

    @classmethod
    def from_dict(cls, data: dict):
        """从字典创建商品"""
        return cls(
            data['product_id'],
            data['name'],
            data['category'],
            data['price'],
            data['stock']
        )

    def __str__(self) -> str:
        """字符串表示"""
        return (f"{self.product_id}\t{self.name}\t{self.category}\t"
                f"¥{self.price:.2f}\t{self.stock}\t¥{self.total_value:.2f}")


# ==================== 订单管理模块 ====================
class Order:
    """订单类"""

    def __init__(self, order_id: str, phone: str, product_id: str,
                 product_name: str, price: float, quantity: int):
        self.order_id = order_id
        self.phone = phone
        self.product_id = product_id
        self.product_name = product_name
        self.price = price
        self.quantity = quantity
        self.total_amount = price * quantity
        self.create_time = datetime.now()
        self.status = 'active'  # active, cancelled

    @staticmethod
    def validate_phone(phone: str) -> bool:
        """验证手机号"""
        return bool(re.match(r'^\d{11}$', phone))

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'order_id': self.order_id,
            'phone': self.phone,
            'product_id': self.product_id,
            'product_name': self.product_name,
            'price': self.price,
            'quantity': self.quantity,
            'total_amount': self.total_amount,
            'create_time': self.create_time.isoformat(),
            'status': self.status
        }

    @classmethod
    def from_dict(cls, data: dict):
        """从字典创建订单"""
        order = cls(
            data['order_id'],
            data['phone'],
            data['product_id'],
            data['product_name'],
            data['price'],
            data['quantity']
        )
        order.total_amount = data['total_amount']
        order.create_time = datetime.fromisoformat(data['create_time'])
        order.status = data.get('status', 'active')
        return order

    def __str__(self) -> str:
        """字符串表示"""
        return (f"订单编号: {self.order_id}\n"
                f"用户手机: {self.phone}\n"
                f"商品编号: {self.product_id}\n"
                f"商品名称: {self.product_name}\n"
                f"单价: ¥{self.price:.2f}\n"
                f"数量: {self.quantity}\n"
                f"总金额: ¥{self.total_amount:.2f}\n"
                f"下单时间: {self.create_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"状态: {'已撤销' if self.status == 'cancelled' else '有效'}")


# ==================== 主系统类 ====================
class MallSystem:
    """商城订单管理系统"""

    def __init__(self):
        self.products: Dict[str, Product] = {}
        self.orders: Dict[str, Order] = {}
        self.logger = Logger()
        self.auth_manager = AuthManager(self.logger)
        self.data_file = 'mall_data.txt'
        self._load_data()

    # ==================== 数据持久化 ====================
    def _load_data(self):
        """从文件加载数据"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    # 加载商品
                    for prod_data in data.get('products', []):
                        product = Product.from_dict(prod_data)
                        self.products[product.product_id] = product

                    # 加载订单
                    for order_data in data.get('orders', []):
                        order = Order.from_dict(order_data)
                        self.orders[order.order_id] = order

                print(f"数据加载成功: {len(self.products)} 个商品, {len(self.orders)} 个订单")
            except Exception as e:
                print(f"数据加载失败: {e}")
                self.logger.error('数据加载', 'System', str(e))

    def _save_data(self):
        """保存数据到文件"""
        try:
            data = {
                'products': [p.to_dict() for p in self.products.values()],
                'orders': [o.to_dict() for o in self.orders.values()]
            }

            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            self.logger.info('数据保存',
                             self.auth_manager.current_user.username if self.auth_manager.current_user else 'System')
        except Exception as e:
            print(f"数据保存失败: {e}")
            self.logger.error('数据保存', 'System', str(e))

    def backup_data(self):
        """备份数据"""
        if not self.auth_manager.check_permission('super'):
            print("权限不足，只有超级管理员才能备份数据")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f'backup_{timestamp}.txt'

        try:
            shutil.copy(self.data_file, backup_file)
            print(f"数据备份成功: {backup_file}")
            self.logger.info('数据备份', self.auth_manager.current_user.username, backup_file)
        except Exception as e:
            print(f"备份失败: {e}")
            self.logger.error('数据备份', self.auth_manager.current_user.username, str(e))

    def restore_data(self):
        """恢复数据"""
        if not self.auth_manager.check_permission('super'):
            print("权限不足，只有超级管理员才能恢复数据")
            return

        # 列出所有备份文件
        backup_files = [f for f in os.listdir('.') if f.startswith('backup_') and f.endswith('.txt')]

        if not backup_files:
            print("没有找到备份文件")
            return

        print("\n可用的备份文件:")
        for i, f in enumerate(backup_files, 1):
            print(f"{i}. {f}")

        try:
            choice = int(input("\n请选择要恢复的备份文件编号: "))
            if 1 <= choice <= len(backup_files):
                backup_file = backup_files[choice - 1]
                shutil.copy(backup_file, self.data_file)
                self._load_data()
                print("数据恢复成功")
                self.logger.info('数据恢复', self.auth_manager.current_user.username, backup_file)
            else:
                print("无效的选择")
        except Exception as e:
            print(f"恢复失败: {e}")
            self.logger.error('数据恢复', self.auth_manager.current_user.username, str(e))

    # ==================== 商品管理功能 ====================
    def add_product(self):
        """添加商品"""
        start_time = time.time()

        print("\n=== 添加商品 ===")

        while True:
            product_id = input("商品编号: ").strip()
            if product_id in self.products:
                print("商品编号已存在，请重新输入")
                continue
            break

        name = input("商品名称: ").strip()
        category = input("商品分类: ").strip()

        while True:
            try:
                price = float(input("单价: "))
                if price <= 0:
                    print("单价必须大于0")
                    continue
                break
            except ValueError:
                print("请输入有效的数字")

        while True:
            try:
                stock = int(input("库存数量: "))
                if stock <= 0:
                    print("库存数量必须大于0")
                    continue
                break
            except ValueError:
                print("请输入有效的整数")

        product = Product(product_id, name, category, price, stock)
        self.products[product_id] = product
        self._save_data()

        elapsed_time = time.time() - start_time
        print("✓ 添加成功")
        self.logger.info('添加商品', self.auth_manager.current_user.username,
                         f'{product_id} - {name}, 响应时间: {elapsed_time:.3f}秒')

    def view_all_products(self):
        """查看所有商品"""
        start_time = time.time()

        print("\n=== 所有商品信息 ===")

        if not self.products:
            print("系统中暂无商品信息")
            return

        print(f"{'商品编号'}\t{'商品名称'}\t{'商品分类'}\t{'单价'}\t{'库存'}\t{'总价值'}")
        print("=" * 80)

        for product in self.products.values():
            print(product)

        print("=" * 80)
        print(f"共 {len(self.products)} 个商品")

        elapsed_time = time.time() - start_time
        self.logger.info('查看商品', self.auth_manager.current_user.username,
                         f'响应时间: {elapsed_time:.3f}秒')

    def delete_product(self):
        """删除商品"""
        if not self.auth_manager.check_permission('super'):
            print("权限不足，只有超级管理员才能删除商品")
            return

        start_time = time.time()

        print("\n=== 删除商品 ===")
        product_id = input("请输入要删除的商品编号: ").strip()

        if product_id not in self.products:
            print("商品不存在")
            return

        product = self.products[product_id]
        confirm = input(f"确认删除商品 [{product.name}] 吗? (yes/no): ").strip().lower()

        if confirm == 'yes':
            del self.products[product_id]
            self._save_data()
            elapsed_time = time.time() - start_time
            print("✓ 删除成功")
            self.logger.info('删除商品', self.auth_manager.current_user.username,
                             f'{product_id} - {product.name}, 响应时间: {elapsed_time:.3f}秒')
        else:
            print("取消删除")

    def modify_product(self):
        """修改商品信息"""
        start_time = time.time()

        print("\n=== 修改商品信息 ===")
        product_id = input("请输入要修改的商品编号: ").strip()

        if product_id not in self.products:
            print("商品不存在")
            return

        product = self.products[product_id]
        print(f"\n当前商品信息:")
        print(product)

        while True:
            print("\n请选择要修改的项目:")
            print("1. 商品名称")
            print("2. 商品分类")
            print("3. 单价")
            print("4. 库存数量")
            print("5. 返回上一级")

            choice = input("请选择 (1-5): ").strip()

            if choice == '1':
                product.name = input("新的商品名称: ").strip()
                print("✓ 修改成功")
            elif choice == '2':
                product.category = input("新的商品分类: ").strip()
                print("✓ 修改成功")
            elif choice == '3':
                try:
                    price = float(input("新的单价: "))
                    if price > 0:
                        product.price = price
                        print("✓ 修改成功")
                    else:
                        print("单价必须大于0")
                except ValueError:
                    print("请输入有效的数字")
            elif choice == '4':
                try:
                    stock = int(input("新的库存数量: "))
                    if stock >= 0:
                        product.stock = stock
                        print("✓ 修改成功")
                    else:
                        print("库存数量不能为负数")
                except ValueError:
                    print("请输入有效的整数")
            elif choice == '5':
                break
            else:
                print("无效的选择")

        self._save_data()
        elapsed_time = time.time() - start_time
        self.logger.info('修改商品', self.auth_manager.current_user.username,
                         f'{product_id}, 响应时间: {elapsed_time:.3f}秒')

    # ==================== 订单管理功能 ====================
    def create_order(self):
        """创建订单 - 带事务保障"""
        start_time = time.time()

        print("\n=== 创建订单 ===")

        # 第一步：收集订单信息
        order_id = input("订单编号: ").strip()
        if order_id in self.orders:
            print("订单编号已存在")
            return

        phone = input("用户手机号: ").strip()
        if not Order.validate_phone(phone):
            print("手机号格式错误，必须是11位纯数字")
            self.logger.warning('创建订单失败', self.auth_manager.current_user.username,
                                f'手机号格式错误: {phone}')
            return

        product_id = input("商品编号: ").strip()

        # 第二步：验证商品存在性
        if product_id not in self.products:
            print("商品不存在")
            self.logger.warning('创建订单失败', self.auth_manager.current_user.username,
                                f'商品不存在: {product_id}')
            return

        product = self.products[product_id]

        try:
            quantity = int(input("购买数量: "))
            if quantity <= 0:
                print("购买数量必须大于0")
                return
        except ValueError:
            print("请输入有效的整数")
            return

        # 第三步：库存检查
        if product.stock < quantity:
            print(f"库存不足！当前库存: {product.stock}")
            self.logger.warning('创建订单失败', self.auth_manager.current_user.username,
                                f'库存不足: {product_id}, 需要{quantity}, 库存{product.stock}')
            return

        # 第四步：执行事务（原子性操作）
        try:
            # 保存原始库存（用于回滚）
            original_stock = product.stock

            # 扣减库存
            product.stock -= quantity

            # 创建订单
            order = Order(order_id, phone, product_id, product.name, product.price, quantity)

            # 提交事务
            self.orders[order_id] = order
            self._save_data()

            elapsed_time = time.time() - start_time
            print("✓ 订单创建成功")
            self.logger.info('创建订单', self.auth_manager.current_user.username,
                             f'{order_id}, 商品: {product_id}, 数量: {quantity}, 响应时间: {elapsed_time:.3f}秒')

        except Exception as e:
            # 回滚操作
            product.stock = original_stock
            print(f"订单创建失败，已回滚: {e}")
            self.logger.error('创建订单', self.auth_manager.current_user.username,
                              f'异常回滚: {str(e)}')

    def query_order(self):
        """查询订单"""
        start_time = time.time()

        print("\n=== 查询订单 ===")
        order_id = input("请输入订单编号: ").strip()

        if order_id not in self.orders:
            print("订单不存在")
            return

        order = self.orders[order_id]
        print(f"\n{order}")

        elapsed_time = time.time() - start_time
        self.logger.info('查询订单', self.auth_manager.current_user.username,
                         f'{order_id}, 响应时间: {elapsed_time:.3f}秒')

    def cancel_order(self):
        """撤销订单"""
        print("\n=== 撤销订单 ===")
        order_id = input("请输入要撤销的订单编号: ").strip()

        if order_id not in self.orders:
            print("订单不存在")
            return

        order = self.orders[order_id]

        if order.status == 'cancelled':
            print("该订单已被撤销")
            return

        # 恢复库存
        if order.product_id in self.products:
            product = self.products[order.product_id]
            product.stock += order.quantity
            order.status = 'cancelled'
            self._save_data()

            print(f"✓ 订单已撤销，已恢复 {order.product_name} 库存 {order.quantity} 件")
            self.logger.info('撤销订单', self.auth_manager.current_user.username,
                             f'{order_id}, 恢复库存: {order.quantity}')
        else:
            print("原商品已不存在，无法恢复库存")

    # ==================== 统计分析功能 ====================
    def order_statistics(self):
        """订单统计分析"""
        start_time = time.time()

        print("\n=== 订单统计分析 ===")

        if not self.orders:
            print("暂无订单数据")
            return

        # 统计各类商品的销售情况
        category_stats = {}

        for order in self.orders.values():
            if order.status != 'active':
                continue

            # 获取商品分类
            if order.product_id in self.products:
                category = self.products[order.product_id].category
            else:
                category = "未知分类"

            if category not in category_stats:
                category_stats[category] = {
                    'quantity': 0,
                    'amount': 0
                }

            category_stats[category]['quantity'] += order.quantity
            category_stats[category]['amount'] += order.total_amount

        print(f"\n{'商品分类'}\t{'销售数量'}\t{'销售总额'}")
        print("=" * 60)

        total_quantity = 0
        total_amount = 0

        for category, stats in category_stats.items():
            print(f"{category}\t{stats['quantity']}\t¥{stats['amount']:.2f}")
            total_quantity += stats['quantity']
            total_amount += stats['amount']

        print("=" * 60)
        print(f"总计\t{total_quantity}\t¥{total_amount:.2f}")
        print(f"\n有效订单数: {sum(1 for o in self.orders.values() if o.status == 'active')}")
        print(f"已撤销订单数: {sum(1 for o in self.orders.values() if o.status == 'cancelled')}")

        elapsed_time = time.time() - start_time
        self.logger.info('订单统计', self.auth_manager.current_user.username,
                         f'响应时间: {elapsed_time:.3f}秒')

    # ==================== 系统菜单 ====================
    def show_menu(self):
        """显示主菜单"""
        print("\n" + "=" * 60)
        print(" " * 20 + "商城订单管理系统")
        print("=" * 60)
        print("1. 添加商品信息")
        print("2. 查看所有商品")
        print("3. 删除商品信息 [超级管理员]")
        print("4. 修改商品信息")
        print("5. 创建用户订单")
        print("6. 查询订单信息")
        print("7. 撤销订单")
        print("8. 订单统计分析")
        print("9. 数据备份 [超级管理员]")
        print("10. 数据恢复 [超级管理员]")
        print("11. 查看系统日志 [超级管理员]")
        print("12. 清空系统日志 [超级管理员]")
        print("0. 退出系统")
        print("=" * 60)

    def run(self):
        """运行系统"""
        print("欢迎使用商城订单管理系统")
        # 默认账号: Admin123/Admin@123 (超级管理员)
        # 默认账号: User123/User@123 (普通管理员)

        print("=" * 60)
        while True:
            text = input("是否拥有账户？（y/n)")
            if text == "n" :
                username = input("用户名: ").strip()
                password = input("密码: ").strip()
                self.auth_manager.register(username,password)
                print("注册成功！")
                continue
            elif text == "y":
            # 登录验证
                while True:
                    print("登录")
                    username = input("用户名: ").strip()
                    password = input("密码: ").strip()

                    if self.auth_manager.login(username, password):
                        break
                break

        # 主循环
        while True:
            self.show_menu()
            choice = input("\n请选择功能 (0-12): ").strip()

            if choice == '1':
                self.add_product()
            elif choice == '2':
                self.view_all_products()
            elif choice == '3':
                self.delete_product()
            elif choice == '4':
                self.modify_product()
            elif choice == '5':
                self.create_order()
            elif choice == '6':
                self.query_order()
            elif choice == '7':
                self.cancel_order()
            elif choice == '8':
                self.order_statistics()
            elif choice == '9':
                self.backup_data()
            elif choice == '10':
                self.restore_data()
            elif choice == '11':
                if self.auth_manager.check_permission('super'):
                    self.logger.view_logs()
                else:
                    print("权限不足，只有超级管理员才能查看日志")
            elif choice == '12':
                if self.auth_manager.check_permission('super'):
                    confirm = input("确认清空所有日志吗? (yes/no): ").strip().lower()
                    if confirm == 'yes':
                        self.logger.clear_logs()
                else:
                    print("权限不足，只有超级管理员才能清空日志")
            elif choice == '0':
                self._save_data()
                self.auth_manager.logout()
                print("\n感谢使用，再见！")
                break
            else:
                print("无效的选择，请重新输入")

            input("\n按回车键继续...")


# ==================== 主程序入口 ====================
if __name__ == '__main__':
    system = MallSystem()
    system.run()
