# 编译器配置
CC = gcc
CFLAGS = -Wall -O2 -I./include

# 目标文件
TARGET = sm2_app
# 源文件列表
# SRCS = src/bignum.c src/main.c
# SRCS = src/bignum.c src/ec.c src/main.c
# 添加 sm3.c 和 sm2.c
# SRCS = src/bignum.c src/ec.c src/sm3.c src/sm2.c src/main.c
SRCS = src/bignum.c src/ec.c src/sm3.c src/sm2.c src/sm2_cert.c src/main.c
OBJS = $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 链接
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# 编译
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -f $(OBJS) $(TARGET)