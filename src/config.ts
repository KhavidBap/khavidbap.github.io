import type {
	ExpressiveCodeConfig,
	LicenseConfig,
	NavBarConfig,
	ProfileConfig,
	SiteConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

export const siteConfig: SiteConfig = {
	title: "Khavid",
	subtitle: "Khavid's blog",
	lang: "en",
	themeColor: {
		hue: 70,
		fixed: true,
	},
	banner: {
		enable: true,
		src: "assets/images/banner.png",
		position: "top",
		credit: {
			enable: true,
			text: "白石杏お誕生日おめでとう!",
			url: "https://www.pixiv.net/en/artworks/120892090",
		},
	},
	toc: {
		enable: true, // Display the table of contents on the right side of the post
		depth: 2, // Maximum heading depth to show in the table, from 1 to 3
	},
	favicon: [
		{
			src: '/favicon/favicon-sunflower.png',              
		}
	],
};

export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home,
		LinkPreset.Archive,
		LinkPreset.About,
		{
			name: "HackMD",
			url: "https://hackmd.io/@khavid",
			external: true,
		},
	],
};

export const profileConfig: ProfileConfig = {
	avatar: "assets/images/avatar.png",
	name: "Khavid",
	bio: "Computer Science VGU'26, interested in Blue team Cybersecurity",
	links: [
		{
			name: "Facebook",
			icon: "fa6-brands:square-facebook",
			url: "https://www.facebook.com/khavid.bap/",
		},
		{
			name: "X (Twitter)",
			icon: "fa6-brands:square-x-twitter",
			url: "https://x.com/KhavidNgo/",
		},
		{
			name: "GitHub",
			icon: "fa6-brands:square-github",
			url: "https://github.com/KhavidBap/",
		},
		{
			name: "LinkedIn",
			icon: "fa6-brands:linkedin",
			url: "https://www.linkedin.com/in/khavidngo/",
		},
	],
};

export const licenseConfig: LicenseConfig = {
	enable: true,
	name: "CC BY-NC-SA 4.0",
	url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
};

export const expressiveCodeConfig: ExpressiveCodeConfig = {
	// Note: Some styles (such as background color) are being overridden, see the astro.config.mjs file.
	// Please select a dark theme, as this blog theme currently only supports dark background color
	theme: "github-dark",
};
