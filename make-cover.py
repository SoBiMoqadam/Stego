from PIL import Image

# ساختن تصویر سفید 200x200
img = Image.new('RGB', (200, 200), (255, 255, 255))
img.save('cover.png')
print("cover.png created")

