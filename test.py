#test.py
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch

# Создание холста
fig, ax = plt.subplots(figsize=(10, 8), dpi=300)
ax.set_xlim(0, 10)
ax.set_ylim(0, 10)
ax.axis('off')

# Цвета
box_color = "#E3F2FD"
text_color = "#1565C0"
arrow_color = "#1976D2"

# Функция для создания блока
def draw_box(x, y, width, height, text, ax):
    box = FancyBboxPatch((x, y), width, height,
                         boxstyle="round,pad=0.1",
                         linewidth=2,
                         edgecolor=text_color,
                         facecolor=box_color)
    ax.add_patch(box)
    ax.text(x + width/2, y + height/2, text,
            ha='center', va='center',
            fontsize=11, fontweight='bold',
            color=text_color,
            wrap=True)

# Блоки
draw_box(1, 8, 8, 1.2, "Вход:\nВектор признаков X = [x1, x2, ..., x10]", ax)
draw_box(1, 6, 8, 1.5, "Для каждого дерева в ансамбле (n=100):\n• Случайный выбор признака\n• Случайный порог разбиения\n• Рекурсивное построение дерева", ax)
draw_box(1, 4, 8, 1, "Вычисление пути изоляции:\ndepth = количество разбиений до листа", ax)
draw_box(1, 2, 8, 1.5, "Ансамбль деревьев:\nСредняя глубина E[depth]\nАnomaly Score = -2^(-E[depth] / c(n))", ax)
draw_box(1, 0.5, 8, 1, "Выход:\nScore ∈ (-∞, 0]\nЧем меньше (отрицательнее) → тем аномальнее", ax)

# Стрелки
def draw_arrow(start, end, ax):
    ax.annotate('', xy=end, xytext=start,
                arrowprops=dict(arrowstyle='->',
                                color=arrow_color,
                                lw=2))

draw_arrow((5, 8), (5, 7.2), ax)
draw_arrow((5, 6), (5, 5), ax)
draw_arrow((5, 4), (5, 3.5), ax)
draw_arrow((5, 2), (5, 1.7), ax)

# Сохранение
plt.savefig('isolation_forest_matplotlib.png',
            dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
plt.close()
print("✅ Схема сохранена как isolation_forest_matplotlib.png")