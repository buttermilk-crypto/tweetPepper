/*
Copyright 2016, David R. Smith, All Rights Reserved

This file is part of TweetPepper.

TweetPepper is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TweetPepper is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TweetPepper.  If not, see <http://www.gnu.org/licenses/>.

*/
package com.cryptoregistry.tweet.pepper.format.img;

import java.awt.Color;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.awt.image.BufferedImageOp;
import java.awt.image.ColorModel;
import java.util.Date;
import java.util.Random;

/**
 * Public interface via factory methods
 * 
 * @author Dave
 *
 */
public class Effects {

	public static BufferedImageOp oilFilter() {
		return new OilFilter();
	}

	public static BufferedImageOp plasmaFilter() {
		return new PlasmaFilter();
	}

}

/*
 * Copyright 2006 Jerry Huxtable
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * A convenience class which implements those methods of BufferedImageOp which
 * are rarely changed.
 */
abstract class AbstractBufferedImageOp implements BufferedImageOp, Cloneable {

	public BufferedImage createCompatibleDestImage(BufferedImage src,
			ColorModel dstCM) {
		if (dstCM == null)
			dstCM = src.getColorModel();
		return new BufferedImage(dstCM, dstCM.createCompatibleWritableRaster(
				src.getWidth(), src.getHeight()), dstCM.isAlphaPremultiplied(),
				null);
	}

	public Rectangle2D getBounds2D(BufferedImage src) {
		return new Rectangle(0, 0, src.getWidth(), src.getHeight());
	}

	public Point2D getPoint2D(Point2D srcPt, Point2D dstPt) {
		if (dstPt == null)
			dstPt = new Point2D.Double();
		dstPt.setLocation(srcPt.getX(), srcPt.getY());
		return dstPt;
	}

	public RenderingHints getRenderingHints() {
		return null;
	}

	/**
	 * A convenience method for getting ARGB pixels from an image. This tries to
	 * avoid the performance penalty of BufferedImage.getRGB unmanaging the
	 * image.
	 * 
	 * @param image
	 *            a BufferedImage object
	 * @param x
	 *            the left edge of the pixel block
	 * @param y
	 *            the right edge of the pixel block
	 * @param width
	 *            the width of the pixel arry
	 * @param height
	 *            the height of the pixel arry
	 * @param pixels
	 *            the array to hold the returned pixels. May be null.
	 * @return the pixels
	 * @see #setRGB
	 */
	public int[] getRGB(BufferedImage image, int x, int y, int width,
			int height, int[] pixels) {
		int type = image.getType();
		if (type == BufferedImage.TYPE_INT_ARGB
				|| type == BufferedImage.TYPE_INT_RGB)
			return (int[]) image.getRaster().getDataElements(x, y, width,
					height, pixels);
		return image.getRGB(x, y, width, height, pixels, 0, width);
	}

	/**
	 * A convenience method for setting ARGB pixels in an image. This tries to
	 * avoid the performance penalty of BufferedImage.setRGB unmanaging the
	 * image.
	 * 
	 * @param image
	 *            a BufferedImage object
	 * @param x
	 *            the left edge of the pixel block
	 * @param y
	 *            the right edge of the pixel block
	 * @param width
	 *            the width of the pixel arry
	 * @param height
	 *            the height of the pixel arry
	 * @param pixels
	 *            the array of pixels to set
	 * @see #getRGB
	 */
	public void setRGB(BufferedImage image, int x, int y, int width,
			int height, int[] pixels) {
		int type = image.getType();
		if (type == BufferedImage.TYPE_INT_ARGB
				|| type == BufferedImage.TYPE_INT_RGB)
			image.getRaster().setDataElements(x, y, width, height, pixels);
		else
			image.setRGB(x, y, width, height, pixels, 0, width);
	}

	public Object clone() {
		try {
			return super.clone();
		} catch (CloneNotSupportedException e) {
			return null;
		}
	}
}

abstract class WholeImageFilter extends AbstractBufferedImageOp {

	/**
	 * The output image bounds.
	 */
	protected Rectangle transformedSpace;

	/**
	 * The input image bounds.
	 */
	protected Rectangle originalSpace;

	/**
	 * Construct a WholeImageFilter.
	 */
	public WholeImageFilter() {
	}

	public BufferedImage filter(BufferedImage src, BufferedImage dst) {
		int width = src.getWidth();
		int height = src.getHeight();
		// int type = src.getType();
		// WritableRaster srcRaster = src.getRaster();

		originalSpace = new Rectangle(0, 0, width, height);
		transformedSpace = new Rectangle(0, 0, width, height);
		transformSpace(transformedSpace);

		if (dst == null) {
			ColorModel dstCM = src.getColorModel();
			dst = new BufferedImage(dstCM,
					dstCM.createCompatibleWritableRaster(
							transformedSpace.width, transformedSpace.height),
					dstCM.isAlphaPremultiplied(), null);
		}
		// WritableRaster dstRaster = dst.getRaster();

		int[] inPixels = getRGB(src, 0, 0, width, height, null);
		inPixels = filterPixels(width, height, inPixels, transformedSpace);
		setRGB(dst, 0, 0, transformedSpace.width, transformedSpace.height,
				inPixels);

		return dst;
	}

	/**
	 * Calculate output bounds for given input bounds.
	 * 
	 * @param rect
	 *            input and output rectangle
	 */
	protected void transformSpace(Rectangle rect) {
	}

	/**
	 * Actually filter the pixels.
	 * 
	 * @param width
	 *            the image width
	 * @param height
	 *            the image height
	 * @param inPixels
	 *            the image pixels
	 * @param transformedSpace
	 *            the output bounds
	 * @return the output pixels
	 */
	protected abstract int[] filterPixels(int width, int height,
			int[] inPixels, Rectangle transformedSpace);
}

interface Colormap {
	/**
	 * Convert a value in the range 0..1 to an RGB color.
	 * 
	 * @param v
	 *            a value in the range 0..1
	 * @return an RGB color
	 */
	public int getColor(float v);
}

class LinearColormap implements Colormap {

	private int color1;
	private int color2;

	/**
	 * Construct a color map with a grayscale ramp from black to white.
	 */
	public LinearColormap() {
		this(0xff000000, 0xffffffff);
	}

	/**
	 * Construct a linear color map.
	 * 
	 * @param color1
	 *            the color corresponding to value 0 in the colormap
	 * @param color2
	 *            the color corresponding to value 1 in the colormap
	 */
	public LinearColormap(int color1, int color2) {
		this.color1 = color1;
		this.color2 = color2;
	}

	/**
	 * Set the first color.
	 * 
	 * @param color1
	 *            the color corresponding to value 0 in the colormap
	 */
	public void setColor1(int color1) {
		this.color1 = color1;
	}

	/**
	 * Get the first color.
	 * 
	 * @return the color corresponding to value 0 in the colormap
	 */
	public int getColor1() {
		return color1;
	}

	/**
	 * Set the second color.
	 * 
	 * @param color2
	 *            the color corresponding to value 1 in the colormap
	 */
	public void setColor2(int color2) {
		this.color2 = color2;
	}

	/**
	 * Get the second color.
	 * 
	 * @return the color corresponding to value 1 in the colormap
	 */
	public int getColor2() {
		return color2;
	}

	/**
	 * Convert a value in the range 0..1 to an RGB color.
	 * 
	 * @param v
	 *            a value in the range 0..1
	 * @return an RGB color
	 */
	public int getColor(float v) {
		return mixColors(clamp(v, 0, 1.0f), color1, color2);
	}

	public float clamp(float x, float a, float b) {
		return (x < a) ? a : (x > b) ? b : x;
	}

	public int mixColors(float t, int rgb1, int rgb2) {
		int a1 = (rgb1 >> 24) & 0xff;
		int r1 = (rgb1 >> 16) & 0xff;
		int g1 = (rgb1 >> 8) & 0xff;
		int b1 = rgb1 & 0xff;
		int a2 = (rgb2 >> 24) & 0xff;
		int r2 = (rgb2 >> 16) & 0xff;
		int g2 = (rgb2 >> 8) & 0xff;
		int b2 = rgb2 & 0xff;
		a1 = lerp(t, a1, a2);
		r1 = lerp(t, r1, r2);
		g1 = lerp(t, g1, g2);
		b1 = lerp(t, b1, b2);
		return (a1 << 24) | (r1 << 16) | (g1 << 8) | b1;
	}

	public static int lerp(float t, int a, int b) {
		return (int) (a + t * (b - a));
	}

}

class OilFilter extends WholeImageFilter {

	private int range = 3;
	private int levels = 256;

	public OilFilter() {
	}

	/**
	 * Set the range of the effect in pixels.
	 * 
	 * @param range
	 *            the range
	 * @see #getRange
	 */
	public void setRange(int range) {
		this.range = range;
	}

	/**
	 * Get the range of the effect in pixels.
	 * 
	 * @return the range
	 * @see #setRange
	 */
	public int getRange() {
		return range;
	}

	/**
	 * Set the number of levels for the effect.
	 * 
	 * @param levels
	 *            the number of levels
	 * @see #getLevels
	 */
	public void setLevels(int levels) {
		this.levels = levels;
	}

	/**
	 * Get the number of levels for the effect.
	 * 
	 * @return the number of levels
	 * @see #setLevels
	 */
	public int getLevels() {
		return levels;
	}

	protected int[] filterPixels(int width, int height, int[] inPixels,
			Rectangle transformedSpace) {
		int index = 0;
		int[] rHistogram = new int[levels];
		int[] gHistogram = new int[levels];
		int[] bHistogram = new int[levels];
		int[] rTotal = new int[levels];
		int[] gTotal = new int[levels];
		int[] bTotal = new int[levels];
		int[] outPixels = new int[width * height];

		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				for (int i = 0; i < levels; i++)
					rHistogram[i] = gHistogram[i] = bHistogram[i] = rTotal[i] = gTotal[i] = bTotal[i] = 0;

				for (int row = -range; row <= range; row++) {
					int iy = y + row;
					int ioffset;
					if (0 <= iy && iy < height) {
						ioffset = iy * width;
						for (int col = -range; col <= range; col++) {
							int ix = x + col;
							if (0 <= ix && ix < width) {
								int rgb = inPixels[ioffset + ix];
								int r = (rgb >> 16) & 0xff;
								int g = (rgb >> 8) & 0xff;
								int b = rgb & 0xff;
								int ri = r * levels / 256;
								int gi = g * levels / 256;
								int bi = b * levels / 256;
								rTotal[ri] += r;
								gTotal[gi] += g;
								bTotal[bi] += b;
								rHistogram[ri]++;
								gHistogram[gi]++;
								bHistogram[bi]++;
							}
						}
					}
				}

				int r = 0, g = 0, b = 0;
				for (int i = 1; i < levels; i++) {
					if (rHistogram[i] > rHistogram[r])
						r = i;
					if (gHistogram[i] > gHistogram[g])
						g = i;
					if (bHistogram[i] > bHistogram[b])
						b = i;
				}
				r = rTotal[r] / rHistogram[r];
				g = gTotal[g] / gHistogram[g];
				b = bTotal[b] / bHistogram[b];
				outPixels[index] = (inPixels[index] & 0xff000000) | (r << 16)
						| (g << 8) | b;
				index++;
			}
		}
		return outPixels;
	}

	public String toString() {
		return "Stylize/Oil...";
	}

}

class PixelUtils {

	public final static int REPLACE = 0;
	public final static int NORMAL = 1;
	public final static int MIN = 2;
	public final static int MAX = 3;
	public final static int ADD = 4;
	public final static int SUBTRACT = 5;
	public final static int DIFFERENCE = 6;
	public final static int MULTIPLY = 7;
	public final static int HUE = 8;
	public final static int SATURATION = 9;
	public final static int VALUE = 10;
	public final static int COLOR = 11;
	public final static int SCREEN = 12;
	public final static int AVERAGE = 13;
	public final static int OVERLAY = 14;
	public final static int CLEAR = 15;
	public final static int EXCHANGE = 16;
	public final static int DISSOLVE = 17;
	public final static int DST_IN = 18;
	public final static int ALPHA = 19;
	public final static int ALPHA_TO_GRAY = 20;

	private static Random randomGenerator = new Random();

	/**
	 * Clamp a value to the range 0..255
	 */
	public static int clamp(int c) {
		if (c < 0)
			return 0;
		if (c > 255)
			return 255;
		return c;
	}

	public static int interpolate(int v1, int v2, float f) {
		return clamp((int) (v1 + f * (v2 - v1)));
	}

	public static int brightness(int rgb) {
		int r = (rgb >> 16) & 0xff;
		int g = (rgb >> 8) & 0xff;
		int b = rgb & 0xff;
		return (r + g + b) / 3;
	}

	public static boolean nearColors(int rgb1, int rgb2, int tolerance) {
		int r1 = (rgb1 >> 16) & 0xff;
		int g1 = (rgb1 >> 8) & 0xff;
		int b1 = rgb1 & 0xff;
		int r2 = (rgb2 >> 16) & 0xff;
		int g2 = (rgb2 >> 8) & 0xff;
		int b2 = rgb2 & 0xff;
		return Math.abs(r1 - r2) <= tolerance && Math.abs(g1 - g2) <= tolerance
				&& Math.abs(b1 - b2) <= tolerance;
	}

	private final static float hsb1[] = new float[3];// FIXME-not thread safe
	private final static float hsb2[] = new float[3];// FIXME-not thread safe

	// Return rgb1 painted onto rgb2
	public static int combinePixels(int rgb1, int rgb2, int op) {
		return combinePixels(rgb1, rgb2, op, 0xff);
	}

	public static int combinePixels(int rgb1, int rgb2, int op, int extraAlpha,
			int channelMask) {
		return (rgb2 & ~channelMask)
				| combinePixels(rgb1 & channelMask, rgb2, op, extraAlpha);
	}

	public static int combinePixels(int rgb1, int rgb2, int op, int extraAlpha) {
		if (op == REPLACE)
			return rgb1;
		int a1 = (rgb1 >> 24) & 0xff;
		int r1 = (rgb1 >> 16) & 0xff;
		int g1 = (rgb1 >> 8) & 0xff;
		int b1 = rgb1 & 0xff;
		int a2 = (rgb2 >> 24) & 0xff;
		int r2 = (rgb2 >> 16) & 0xff;
		int g2 = (rgb2 >> 8) & 0xff;
		int b2 = rgb2 & 0xff;

		switch (op) {
		case NORMAL:
			break;
		case MIN:
			r1 = Math.min(r1, r2);
			g1 = Math.min(g1, g2);
			b1 = Math.min(b1, b2);
			break;
		case MAX:
			r1 = Math.max(r1, r2);
			g1 = Math.max(g1, g2);
			b1 = Math.max(b1, b2);
			break;
		case ADD:
			r1 = clamp(r1 + r2);
			g1 = clamp(g1 + g2);
			b1 = clamp(b1 + b2);
			break;
		case SUBTRACT:
			r1 = clamp(r2 - r1);
			g1 = clamp(g2 - g1);
			b1 = clamp(b2 - b1);
			break;
		case DIFFERENCE:
			r1 = clamp(Math.abs(r1 - r2));
			g1 = clamp(Math.abs(g1 - g2));
			b1 = clamp(Math.abs(b1 - b2));
			break;
		case MULTIPLY:
			r1 = clamp(r1 * r2 / 255);
			g1 = clamp(g1 * g2 / 255);
			b1 = clamp(b1 * b2 / 255);
			break;
		case DISSOLVE:
			if ((randomGenerator.nextInt() & 0xff) <= a1) {
				r1 = r2;
				g1 = g2;
				b1 = b2;
			}
			break;
		case AVERAGE:
			r1 = (r1 + r2) / 2;
			g1 = (g1 + g2) / 2;
			b1 = (b1 + b2) / 2;
			break;
		case HUE:
		case SATURATION:
		case VALUE:
		case COLOR:
			Color.RGBtoHSB(r1, g1, b1, hsb1);
			Color.RGBtoHSB(r2, g2, b2, hsb2);
			switch (op) {
			case HUE:
				hsb2[0] = hsb1[0];
				break;
			case SATURATION:
				hsb2[1] = hsb1[1];
				break;
			case VALUE:
				hsb2[2] = hsb1[2];
				break;
			case COLOR:
				hsb2[0] = hsb1[0];
				hsb2[1] = hsb1[1];
				break;
			}
			rgb1 = Color.HSBtoRGB(hsb2[0], hsb2[1], hsb2[2]);
			r1 = (rgb1 >> 16) & 0xff;
			g1 = (rgb1 >> 8) & 0xff;
			b1 = rgb1 & 0xff;
			break;
		case SCREEN:
			r1 = 255 - ((255 - r1) * (255 - r2)) / 255;
			g1 = 255 - ((255 - g1) * (255 - g2)) / 255;
			b1 = 255 - ((255 - b1) * (255 - b2)) / 255;
			break;
		case OVERLAY:
			int m,
			s;
			s = 255 - ((255 - r1) * (255 - r2)) / 255;
			m = r1 * r2 / 255;
			r1 = (s * r1 + m * (255 - r1)) / 255;
			s = 255 - ((255 - g1) * (255 - g2)) / 255;
			m = g1 * g2 / 255;
			g1 = (s * g1 + m * (255 - g1)) / 255;
			s = 255 - ((255 - b1) * (255 - b2)) / 255;
			m = b1 * b2 / 255;
			b1 = (s * b1 + m * (255 - b1)) / 255;
			break;
		case CLEAR:
			r1 = g1 = b1 = 0xff;
			break;
		case DST_IN:
			r1 = clamp((r2 * a1) / 255);
			g1 = clamp((g2 * a1) / 255);
			b1 = clamp((b2 * a1) / 255);
			a1 = clamp((a2 * a1) / 255);
			return (a1 << 24) | (r1 << 16) | (g1 << 8) | b1;
		case ALPHA:
			a1 = a1 * a2 / 255;
			return (a1 << 24) | (r2 << 16) | (g2 << 8) | b2;
		case ALPHA_TO_GRAY:
			int na = 255 - a1;
			return (a1 << 24) | (na << 16) | (na << 8) | na;
		}
		if (extraAlpha != 0xff || a1 != 0xff) {
			a1 = a1 * extraAlpha / 255;
			int a3 = (255 - a1) * a2 / 255;
			r1 = clamp((r1 * a1 + r2 * a3) / 255);
			g1 = clamp((g1 * a1 + g2 * a3) / 255);
			b1 = clamp((b1 * a1 + b2 * a3) / 255);
			a1 = clamp(a1 + a3);
		}
		return (a1 << 24) | (r1 << 16) | (g1 << 8) | b1;
	}

}

class PlasmaFilter extends WholeImageFilter {

	public float turbulence = 1.0f;
	private float scaling = 0.0f;
	private Colormap colormap = new LinearColormap();
	private Random randomGenerator;
	private long seed = 567;
	private boolean useColormap = false;
	private boolean useImageColors = false;

	public PlasmaFilter() {
		randomGenerator = new Random();
	}

	/**
	 * Specifies the turbulence of the texture.
	 * 
	 * @param turbulence
	 *            the turbulence of the texture.
	 * @min-value 0
	 * @max-value 10
	 * @see #getTurbulence
	 */
	public void setTurbulence(float turbulence) {
		this.turbulence = turbulence;
	}

	/**
	 * Returns the turbulence of the effect.
	 * 
	 * @return the turbulence of the effect.
	 * @see #setTurbulence
	 */
	public float getTurbulence() {
		return turbulence;
	}

	public void setScaling(float scaling) {
		this.scaling = scaling;
	}

	public float getScaling() {
		return scaling;
	}

	/**
	 * Set the colormap to be used for the filter.
	 * 
	 * @param colormap
	 *            the colormap
	 * @see #getColormap
	 */
	public void setColormap(Colormap colormap) {
		this.colormap = colormap;
	}

	/**
	 * Get the colormap to be used for the filter.
	 * 
	 * @return the colormap
	 * @see #setColormap
	 */
	public Colormap getColormap() {
		return colormap;
	}

	public void setUseColormap(boolean useColormap) {
		this.useColormap = useColormap;
	}

	public boolean getUseColormap() {
		return useColormap;
	}

	public void setUseImageColors(boolean useImageColors) {
		this.useImageColors = useImageColors;
	}

	public boolean getUseImageColors() {
		return useImageColors;
	}

	public void setSeed(int seed) {
		this.seed = seed;
	}

	public int getSeed() {
		return (int) seed;
	}

	public void randomize() {
		seed = new Date().getTime();
	}

	private int randomRGB(int[] inPixels, int x, int y) {
		if (useImageColors) {
			return inPixels[y * originalSpace.width + x];
		} else {
			int r = (int) (255 * randomGenerator.nextFloat());
			int g = (int) (255 * randomGenerator.nextFloat());
			int b = (int) (255 * randomGenerator.nextFloat());
			return 0xff000000 | (r << 16) | (g << 8) | b;
		}
	}

	private int displace(int rgb, float amount) {
		int r = (rgb >> 16) & 0xff;
		int g = (rgb >> 8) & 0xff;
		int b = rgb & 0xff;
		r = PixelUtils.clamp(r
				+ (int) (amount * (randomGenerator.nextFloat() - 0.5)));
		g = PixelUtils.clamp(g
				+ (int) (amount * (randomGenerator.nextFloat() - 0.5)));
		b = PixelUtils.clamp(b
				+ (int) (amount * (randomGenerator.nextFloat() - 0.5)));
		return 0xff000000 | (r << 16) | (g << 8) | b;
	}

	private int average(int rgb1, int rgb2) {
		return PixelUtils.combinePixels(rgb1, rgb2, PixelUtils.AVERAGE);
	}

	private int getPixel(int x, int y, int[] pixels, int stride) {
		return pixels[y * stride + x];
	}

	private void putPixel(int x, int y, int rgb, int[] pixels, int stride) {
		pixels[y * stride + x] = rgb;
	}

	private boolean doPixel(int x1, int y1, int x2, int y2, int[] pixels,
			int stride, int depth, int scale) {
		int mx, my;

		if (depth == 0) {
			int ml, mr, mt, mb, mm, t;

			int tl = getPixel(x1, y1, pixels, stride);
			int bl = getPixel(x1, y2, pixels, stride);
			int tr = getPixel(x2, y1, pixels, stride);
			int br = getPixel(x2, y2, pixels, stride);

			float amount = (256.0f / (2.0f * scale)) * turbulence;

			mx = (x1 + x2) / 2;
			my = (y1 + y2) / 2;

			if (mx == x1 && mx == x2 && my == y1 && my == y2)
				return true;

			if (mx != x1 || mx != x2) {
				ml = average(tl, bl);
				ml = displace(ml, amount);
				putPixel(x1, my, ml, pixels, stride);

				if (x1 != x2) {
					mr = average(tr, br);
					mr = displace(mr, amount);
					putPixel(x2, my, mr, pixels, stride);
				}
			}

			if (my != y1 || my != y2) {
				if (x1 != mx || my != y2) {
					mb = average(bl, br);
					mb = displace(mb, amount);
					putPixel(mx, y2, mb, pixels, stride);
				}

				if (y1 != y2) {
					mt = average(tl, tr);
					mt = displace(mt, amount);
					putPixel(mx, y1, mt, pixels, stride);
				}
			}

			if (y1 != y2 || x1 != x2) {
				mm = average(tl, br);
				t = average(bl, tr);
				mm = average(mm, t);
				mm = displace(mm, amount);
				putPixel(mx, my, mm, pixels, stride);
			}

			if (x2 - x1 < 3 && y2 - y1 < 3)
				return false;
			return true;
		}

		mx = (x1 + x2) / 2;
		my = (y1 + y2) / 2;

		doPixel(x1, y1, mx, my, pixels, stride, depth - 1, scale + 1);
		doPixel(x1, my, mx, y2, pixels, stride, depth - 1, scale + 1);
		doPixel(mx, y1, x2, my, pixels, stride, depth - 1, scale + 1);
		return doPixel(mx, my, x2, y2, pixels, stride, depth - 1, scale + 1);
	}

	protected int[] filterPixels(int width, int height, int[] inPixels,
			Rectangle transformedSpace) {
		int[] outPixels = new int[width * height];

		randomGenerator.setSeed(seed);

		int w1 = width - 1;
		int h1 = height - 1;
		putPixel(0, 0, randomRGB(inPixels, 0, 0), outPixels, width);
		putPixel(w1, 0, randomRGB(inPixels, w1, 0), outPixels, width);
		putPixel(0, h1, randomRGB(inPixels, 0, h1), outPixels, width);
		putPixel(w1, h1, randomRGB(inPixels, w1, h1), outPixels, width);
		putPixel(w1 / 2, h1 / 2, randomRGB(inPixels, w1 / 2, h1 / 2),
				outPixels, width);
		putPixel(0, h1 / 2, randomRGB(inPixels, 0, h1 / 2), outPixels, width);
		putPixel(w1, h1 / 2, randomRGB(inPixels, w1, h1 / 2), outPixels, width);
		putPixel(w1 / 2, 0, randomRGB(inPixels, w1 / 2, 0), outPixels, width);
		putPixel(w1 / 2, h1, randomRGB(inPixels, w1 / 2, h1), outPixels, width);

		int depth = 1;
		while (doPixel(0, 0, width - 1, height - 1, outPixels, width, depth, 0))
			depth++;

		if (useColormap && colormap != null) {
			int index = 0;
			for (int y = 0; y < height; y++) {
				for (int x = 0; x < width; x++) {
					outPixels[index] = colormap
							.getColor((outPixels[index] & 0xff) / 255.0f);
					index++;
				}
			}
		}
		return outPixels;
	}

	public String toString() {
		return "Texture/Plasma...";
	}

}
