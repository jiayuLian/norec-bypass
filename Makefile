export ARCHS = arm64
export TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

# 用 LIBRARY_NAME 而不是 TWEAK_NAME：
#   TWEAK_NAME + tweak.mk 会套一层 Logos 默认生成器（MobileSubstrate），
#   带出 CydiaSubstrate 依赖 → TrollStore/TrollFools 设备上 dyld 加载即崩。
#   LIBRARY_NAME + library.mk 是纯 dylib 构建，产出
#   .theos/obj/arm64/NoRecBypass.dylib，没有任何 MobileSubstrate 语义。
LIBRARY_NAME = NoRecBypass

NoRecBypass_FILES = Tweak.m
NoRecBypass_CFLAGS = -fobjc-arc -Wall \
                     -Wno-deprecated-declarations \
                     -Wno-unused-function \
                     -Wno-unused-variable \
                     -Wno-unused-parameter \
                     -Wno-cast-function-type \
                     -Wno-cast-function-type-strict \
                     -Wno-nullability-completeness \
                     -Wno-unknown-warning-option
# 只用 Foundation。UIKit / AVFoundation 的类一律走 NSClassFromString，
# 不做符号引用 → 不必链，也就不会在旧 SDK 上因漏链而 undefined。
NoRecBypass_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/library.mk
