import embqr
from lxml import etree
import math
import os

logoPath = os.path.join(os.path.dirname(os.path.abspath(__file__)),r'static\icons\cblo6-emc8f.svg')
#logoPath = r"D:\Pycharms\VirtualEnv\Flask\ElfinURL\static\icons\cblo6-emc8f.svg"

block_size = 10
circle_radius = block_size * 4

def distance(p0, p1):
    return math.sqrt((p0[0] - p1[0])**2 + (p0[1] - p1[1])**2)

def generateQRImageForUrl(url):
    qr_image = embqr.MakeQRImage(url, errorCorrectLevel = embqr.QRErrorCorrectLevel.H, block_in_pixels = 1, border_in_blocks=0)
    return qr_image

def getSVGFileContent(filename):
    document = etree.parse(filename)
    svg = document.xpath('//*[local-name()="svg"]')[0]
    return svg

def touchesBounds(center, x, y, radius, block_size):
    scaled_center = center / block_size
    dis = distance((scaled_center , scaled_center), (x, y))
    rad = radius / block_size
    return dis <= rad + 1

def create_emb_qr(url):
    im = generateQRImageForUrl(url)

    imageSize = str(im.size[0] * block_size)

    # create an SVG XML element (see the SVG specification for attribute details)
    doc = etree.Element('svg', width=imageSize, height=imageSize, version='1.1', xmlns='http://www.w3.org/2000/svg')

    pix = im.load()

    center = im.size[0] * block_size / 2

    for xPos in range(0, im.size[0]):
        for yPos in range(0, im.size[1]):

            color = pix[xPos, yPos]
            if color == (0, 0, 0, 255):

                withinBounds = not touchesBounds(center, xPos, yPos, circle_radius, block_size)

                if (withinBounds):
                    etree.SubElement(doc, 'rect', x=str(xPos * block_size), y=str(yPos * block_size), width='10',
                                     height='10', fill='black')

    logo = getSVGFileContent(logoPath)

    test = str(logo.get("viewBox"))
    Array = []

    if (test != "None"):
        Array = test.split(" ")
        width = float(Array[2])
        height = float(Array[3])
    else:
        width = float(str(logo.get("width")).replace("px", ""))
        height = float(str(logo.get("height")).replace("px", ""))

    dim = height
    if (width > dim):
        dim = width
    scale = circle_radius * 2.0 / width

    scale_str = "scale(" + str(scale) + ")"

    xTrans = ((im.size[0] * block_size) - (width * scale)) / 2.0
    yTrans = ((im.size[1] * block_size) - (height * scale)) / 2.0

    translate = "translate(" + str(xTrans) + " " + str(yTrans) + ")"

    logo_scale_container = etree.SubElement(doc, 'g', transform=translate + " " + scale_str)

    for element in logo.getchildren():
        logo_scale_container.append(element)

    # ElementTree 1.2 doesn't write the SVG file header errata, so do that manually
    header = "<?xml version=\"1.0\" standalone=\"no\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\"\n\"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n"
    return header+etree.tostring(doc)

