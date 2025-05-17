import mongoose, { Schema } from "mongoose";

const colors = ["#E4080A", "#7DDA58", "#3357FF", "#FF33A6", "#A633FF", "#FF8F33"];

//A func to generate Google like avatar (Letter on background)
const generateAvatarSVG = (fullname) => {
    const bgColor = colors[Math.floor(Math.random() * colors.length)];
    const firstLetter = fullname && fullname[0] ? fullname[0].toUpperCase() : "?";

    return `
        <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">
            <rect width="100" height="100" fill="${bgColor}" />
            <text x="50%" y="50%" font-size="50" fill="white" text-anchor="middle" dominant-baseline="central" font-family="Arial, sans-serif">
                ${firstLetter}
            </text>
        </svg>
    `;
};

const userSchema = mongoose.Schema(
    {
        personal_info: {
            fullname: {
                type: String,
                lowercase: true,
                required: true,
                minlength: [4, "fullname must be 4 letters long"],
            },
            email: {
                type: String,
                required: true,
                lowercase: true,
                unique: true,
            },
            password: String,
            username: {
                type: String,
                minlength: [4, "Username must be 4 letters long"],
                unique: true,
            },
            bio: {
                type: String,
                maxlength: [200, "Bio should not be more than 200"],
                default: "",
            },
            profile_img: {
                type: String,
            },
        },

        admin: {
            type: Boolean,
            default: false
        },

        blocked: {
            type: Boolean,
            default: false
        },

        social_links: {
            youtube: {
                type: String,
                default: "",
            },
            instagram: {
                type: String,
                default: "",
            },
            facebook: {
                type: String,
                default: "",
            },
            twitter: {
                type: String,
                default: "",
            },
            github: {
                type: String,
                default: "",
            },
            website: {
                type: String,
                default: "",
            },
        },
        account_info: {
            total_posts: {
                type: Number,
                default: 0,
            },
            total_reads: {
                type: Number,
                default: 0,
            },
        },
        provider_auth: {
            type: Boolean,
            default: false,
        },
        posts: {
            type: [Schema.Types.ObjectId],
            ref: "posts",
            default: [],
        },
    },
    {
        timestamps: {
            createdAt: "joinedAt",
        },
    }
);

//Middleware for setting avatar before saving to db
userSchema.pre("save", function (next) {
    if (!this.personal_info.profile_img) {
        const fullname = this.personal_info.fullname || "Unknown";
        const svg = generateAvatarSVG(fullname);
        this.personal_info.profile_img = `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;
    }
    next();
});

export default mongoose.model("users", userSchema);
