/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
/***/ ((module) => {

module.exports = require("tslib");

/***/ }),
/* 2 */
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),
/* 3 */
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),
/* 4 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const app_controller_1 = __webpack_require__(5);
const app_service_1 = __webpack_require__(6);
const mongoose_1 = __webpack_require__(10);
const shared_config_1 = __webpack_require__(25);
const shared_schema_1 = __webpack_require__(20);
const shared_repositories_1 = __webpack_require__(7);
const passport_1 = __webpack_require__(35);
const jwt_1 = __webpack_require__(13);
const authConf_1 = __webpack_require__(33);
const refreshtoken_schema_1 = __webpack_require__(39);
const otp_schema_1 = __webpack_require__(19);
const otp_service_service_1 = __webpack_require__(16);
const config = (0, shared_config_1.sharedConfig)();
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [mongoose_1.MongooseModule.forRoot(config.db_url, { dbName: 'veloGo' }),
            mongoose_1.MongooseModule.forFeature([{ name: "User", schema: shared_schema_1.UserSchema }, { name: "RefreshToken", schema: refreshtoken_schema_1.RefreshTokenSchema }, { name: "Otp", schema: otp_schema_1.OtpSchema }]),
            passport_1.PassportModule,
            jwt_1.JwtModule.register({
                secret: config.privateKey, // Use environment variable for production
                signOptions: { expiresIn: '3m', algorithm: 'RS256' },
            }),
        ],
        controllers: [app_controller_1.AppController],
        providers: [app_service_1.AppService, otp_service_service_1.OtpServiceService, shared_repositories_1.UserRepository, authConf_1.JwtStrategy],
        exports: [shared_repositories_1.UserRepository]
    })
], AppModule);


/***/ }),
/* 5 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppController = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const app_service_1 = __webpack_require__(6);
const create_user_dto_1 = __webpack_require__(30);
const express_1 = __webpack_require__(32);
const authConf_1 = __webpack_require__(33);
const cookie_util_1 = __webpack_require__(38);
const otp_service_service_1 = __webpack_require__(16);
let AppController = class AppController {
    constructor(appService, otpService) {
        this.appService = appService;
        this.otpService = otpService;
    }
    async signup(res, req) {
        await this.appService.signup(req);
        res.status(common_1.HttpStatus.CREATED).json({ success: true, message: "sent otp to your email!" });
    }
    async login(res, req) {
        await this.appService.login(req);
        res.status(common_1.HttpStatus.OK).json({ success: true, message: "sent otp to your email!" });
    }
    async verifyOtp(flow, res, req) {
        // If this is a forgot-password flow, ensure a new password was provided
        if (flow === 'forgot-password' && !req.password) {
            throw new common_1.BadRequestException('New password is required for password reset.');
        }
        let message;
        if (flow === 'forgot-password') {
            // Validate OTP & reset the password (no tokens issued)
            await this.appService.validate(req);
            message = 'Password reset successful!';
        }
        else {
            // signup or login: validate OTP and issue tokens
            const { authToken, refreshToken } = await this.appService.validate(req);
            (0, cookie_util_1.makeCookies)(res, authToken, refreshToken);
            message = flow === 'signup' ? 'Signup successful!' : 'Login successful!';
        }
        return res.status(common_1.HttpStatus.OK).json({ success: true, message });
    }
    async refresh(res, req) {
        const refreshTo = req.cookies.refreshToken;
        if (!refreshTo)
            throw new common_1.UnauthorizedException("No Refresh Token found!");
        const { authToken, refreshToken } = await this.appService.refreshToken(refreshTo);
        (0, cookie_util_1.makeCookies)(res, authToken, refreshToken);
        res.status(common_1.HttpStatus.OK).json({ success: true, info: "Refresh and Access tokens set successfully!" });
    }
    async getUser(req, res) {
        //TODO: add type to req
        const { _id } = req.user;
        const user = await this.appService.getUser(_id);
        res.status(common_1.HttpStatus.OK).json({ success: true, user: user });
    }
    async forgotPassword(req, res) {
        await this.appService.forgot(req);
        res.status(common_1.HttpStatus.OK).json({ success: true, message: "sent otp to your email!" });
    }
};
exports.AppController = AppController;
tslib_1.__decorate([
    (0, common_1.Post)('signup/request-otp'),
    tslib_1.__param(0, (0, common_1.Res)({ passthrough: true })),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_c = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _c : Object, typeof (_d = typeof create_user_dto_1.CreateUserDTO !== "undefined" && create_user_dto_1.CreateUserDTO) === "function" ? _d : Object]),
    tslib_1.__metadata("design:returntype", Promise)
], AppController.prototype, "signup", null);
tslib_1.__decorate([
    (0, common_1.Post)('login/request-otp'),
    tslib_1.__param(0, (0, common_1.Res)({ passthrough: true })),
    tslib_1.__param(1, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_e = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _e : Object, Object]),
    tslib_1.__metadata("design:returntype", Promise)
], AppController.prototype, "login", null);
tslib_1.__decorate([
    (0, common_1.Post)(':flow(signup|login|forgot-password)/verify-otp'),
    tslib_1.__param(0, (0, common_1.Param)('flow')),
    tslib_1.__param(1, (0, common_1.Res)({ passthrough: true })),
    tslib_1.__param(2, (0, common_1.Body)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [String, typeof (_f = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _f : Object, Object]),
    tslib_1.__metadata("design:returntype", Promise)
], AppController.prototype, "verifyOtp", null);
tslib_1.__decorate([
    (0, common_1.Post)('refresh'),
    tslib_1.__param(0, (0, common_1.Res)({ passthrough: true })),
    tslib_1.__param(1, (0, common_1.Req)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_g = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _g : Object, Object]),
    tslib_1.__metadata("design:returntype", Promise)
], AppController.prototype, "refresh", null);
tslib_1.__decorate([
    (0, common_1.UseGuards)(authConf_1.JwtAuthGuard),
    (0, common_1.Get)(''),
    tslib_1.__param(0, (0, common_1.Req)()),
    tslib_1.__param(1, (0, common_1.Res)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_k = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _k : Object]),
    tslib_1.__metadata("design:returntype", Promise)
], AppController.prototype, "getUser", null);
tslib_1.__decorate([
    (0, common_1.Post)('forgot-password'),
    tslib_1.__param(0, (0, common_1.Body)()),
    tslib_1.__param(1, (0, common_1.Res)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object, typeof (_l = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _l : Object]),
    tslib_1.__metadata("design:returntype", Promise)
], AppController.prototype, "forgotPassword", null);
exports.AppController = AppController = tslib_1.__decorate([
    (0, common_1.Controller)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof app_service_1.AppService !== "undefined" && app_service_1.AppService) === "function" ? _a : Object, typeof (_b = typeof otp_service_service_1.OtpServiceService !== "undefined" && otp_service_service_1.OtpServiceService) === "function" ? _b : Object])
], AppController);


/***/ }),
/* 6 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppService = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const shared_repositories_1 = __webpack_require__(7);
const mongoose_1 = __webpack_require__(10);
const mongoose_2 = __webpack_require__(11);
const bcrypt = tslib_1.__importStar(__webpack_require__(12));
const jwt_1 = __webpack_require__(13);
const uuid_1 = __webpack_require__(14);
const crypto_1 = __webpack_require__(15);
const otp_service_service_1 = __webpack_require__(16);
let AppService = class AppService {
    constructor(userRepository, userModel, refreshTokenModel, jwtService, otpService) {
        this.userRepository = userRepository;
        this.userModel = userModel;
        this.refreshTokenModel = refreshTokenModel;
        this.jwtService = jwtService;
        this.otpService = otpService;
    }
    async signup(createUserDTO) {
        try {
            const { email } = createUserDTO;
            const existingUser = await this.userRepository.findByEmail(email);
            // TODO: make new exception for this
            if (existingUser)
                throw new common_1.BadRequestException('User Already Exists!');
            const newUser = new this.userModel(createUserDTO);
            const user = await newUser.save();
            await this.otpService.sendOtp(user);
            return await this.generateTokens(user._id.toString());
        }
        catch (e) {
            throw new common_1.BadRequestException(e.message);
        }
    }
    async login(req) {
        const { email, password } = req;
        const user = await this.userRepository.findByEmail(email);
        if (!user) {
            throw new common_1.NotFoundException('Either Email or Password are wrong!');
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            throw new common_1.NotFoundException('Incorrect Password!');
        }
        const sent = await this.otpService.sendOtp(user);
        if (!sent)
            throw new common_1.BadRequestException('Unable to send OTP!');
        return;
    }
    async forgot(req) {
        const { email } = req;
        const user = await this.userRepository.findByEmail(email);
        if (!user)
            throw new common_1.NotFoundException('User not found!');
        const sent = await this.otpService.sendOtp(user);
        if (!sent)
            throw new common_1.BadRequestException('Unable to send OTP!');
    }
    async validate(req) {
        const userData = await this.userRepository.findByEmail(req.email);
        if (!userData)
            throw new common_1.NotFoundException('User not found!');
        const match = await this.otpService.validateOtp(userData, req.otp, req.password);
        if (!match)
            throw new common_1.UnauthorizedException('Invalid OTP!');
        return await this.generateTokens(userData._id.toString());
    }
    async refreshToken(oldToken) {
        const tokenData = await this.refreshTokenModel.findOne({ token: oldToken });
        if (!tokenData || tokenData.expires < new Date())
            throw new common_1.UnauthorizedException('Refresh Token expired! Pleas login again!');
        await this.refreshTokenModel.findByIdAndDelete(tokenData._id);
        return await this.generateTokens(tokenData.userId.toString());
    }
    async getUser(userId) {
        const user = await this.userRepository.findById(userId);
        console.log(user);
        if (!user)
            throw new common_1.NotFoundException('Not found!');
        return user;
    }
    async generateTokens(userId) {
        const refreshToken = (0, crypto_1.randomBytes)(64).toString('hex');
        const tokenIndex = (0, uuid_1.v4)();
        const expires = new Date();
        expires.setDate(expires.getDate() + 7);
        await this.refreshTokenModel.create({
            userId: userId,
            token: refreshToken,
            expires,
            tokenIndex,
        });
        const authToken = this.jwtService.sign({ _id: userId });
        return { authToken, refreshToken };
    }
};
exports.AppService = AppService;
exports.AppService = AppService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(1, (0, mongoose_1.InjectModel)('User')),
    tslib_1.__param(2, (0, mongoose_1.InjectModel)('RefreshToken')),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof shared_repositories_1.UserRepository !== "undefined" && shared_repositories_1.UserRepository) === "function" ? _a : Object, typeof (_b = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _b : Object, typeof (_c = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _c : Object, typeof (_d = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _d : Object, typeof (_e = typeof otp_service_service_1.OtpServiceService !== "undefined" && otp_service_service_1.OtpServiceService) === "function" ? _e : Object])
], AppService);


/***/ }),
/* 7 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(1);
tslib_1.__exportStar(__webpack_require__(8), exports);
tslib_1.__exportStar(__webpack_require__(9), exports);


/***/ }),
/* 8 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SharedRepositoriesModule = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
let SharedRepositoriesModule = class SharedRepositoriesModule {
};
exports.SharedRepositoriesModule = SharedRepositoriesModule;
exports.SharedRepositoriesModule = SharedRepositoriesModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [],
        providers: [],
        exports: [],
    })
], SharedRepositoriesModule);


/***/ }),
/* 9 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserRepository = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const mongoose_1 = __webpack_require__(10);
const mongoose_2 = __webpack_require__(11);
let UserRepository = class UserRepository {
    constructor(userModel) {
        this.userModel = userModel;
    }
    async findByEmail(email) {
        return this.userModel.findOne({ email }).exec();
    }
    async findById(id) {
        return this.userModel.findById(id);
    }
};
exports.UserRepository = UserRepository;
exports.UserRepository = UserRepository = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)('User')),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object])
], UserRepository);


/***/ }),
/* 10 */
/***/ ((module) => {

module.exports = require("@nestjs/mongoose");

/***/ }),
/* 11 */
/***/ ((module) => {

module.exports = require("mongoose");

/***/ }),
/* 12 */
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),
/* 13 */
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),
/* 14 */
/***/ ((module) => {

module.exports = require("uuid");

/***/ }),
/* 15 */
/***/ ((module) => {

module.exports = require("crypto");

/***/ }),
/* 16 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OtpServiceService = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const twilio_1 = __webpack_require__(17);
const nodemailer = tslib_1.__importStar(__webpack_require__(18));
const mongoose_1 = __webpack_require__(10);
const otp_schema_1 = __webpack_require__(19);
const shared_schema_1 = __webpack_require__(20);
const auth_config_1 = __webpack_require__(23);
const mongoose_2 = __webpack_require__(11);
const shared_config_1 = __webpack_require__(25);
let OtpServiceService = class OtpServiceService {
    constructor(otpModel, userModel) {
        this.otpModel = otpModel;
        this.userModel = userModel;
        this.config = (0, auth_config_1.authConfig)(); // just like sharedConfig()
        this.mainConf = (0, shared_config_1.sharedConfig)();
        this.twilioClient = new twilio_1.Twilio(this.config.twilio_sid, this.config.twilio_token);
        this.mailer = nodemailer.createTransport({
            service: 'gmail',
            auth: this.mainConf.nodemailer_auth,
        });
    }
    generateOtp() {
        return Math.floor(10 ** 6 + Math.random() * 9 * 10 ** 5).toString();
    }
    async sendOtp(user) {
        try {
            console.log(user._id);
            await this.otpModel.deleteMany({ userId: user._id });
            const otp = this.generateOtp();
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
            await this.otpModel.create({
                otp,
                expiresAt,
                userId: user._id
            });
            // await this.twilioClient.messages.create({
            //   body: `Your OTP is ${otp}. This OTP expires in 5 minutes.`,
            //   from: this.config.twilio_from,
            //   to: "+91"+user.phone,
            // })
            await this.mailer.sendMail({
                to: user.email,
                from: this.mainConf.nodemailer_auth.user,
                subject: "OTP Code",
                html: `Your OTP is ${otp}. This OTP expires in 5 minutes.`
            });
            return true;
        }
        catch (e) {
            console.log(e.message);
            return false;
        }
    }
    async validateOtp(user, otp, password) {
        const userRec = await this.otpModel.findOne({ otp, userId: user._id, expiresAt: { $gt: new Date() } });
        console.log(userRec);
        if (userRec.userId.toString() !== user._id.toString())
            return false;
        if (password) {
            const userEntry = await this.userModel.findOne({ _id: user._id });
            userEntry.password = password;
            await userEntry.save();
        }
        return true;
    }
};
exports.OtpServiceService = OtpServiceService;
exports.OtpServiceService = OtpServiceService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__param(0, (0, mongoose_1.InjectModel)(otp_schema_1.Otp.name)),
    tslib_1.__param(1, (0, mongoose_1.InjectModel)(shared_schema_1.User.name)),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _b : Object])
], OtpServiceService);


/***/ }),
/* 17 */
/***/ ((module) => {

module.exports = require("twilio");

/***/ }),
/* 18 */
/***/ ((module) => {

module.exports = require("nodemailer");

/***/ }),
/* 19 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OtpSchema = exports.Otp = void 0;
const tslib_1 = __webpack_require__(1);
const mongoose_1 = __webpack_require__(10);
const mongoose_2 = __webpack_require__(11);
const shared_schema_1 = __webpack_require__(20);
let Otp = class Otp extends mongoose_2.Document {
};
exports.Otp = Otp;
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, index: true }),
    tslib_1.__metadata("design:type", String)
], Otp.prototype, "otp", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], Otp.prototype, "expiresAt", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.Types.ObjectId, ref: shared_schema_1.User.name, required: true }),
    tslib_1.__metadata("design:type", String)
], Otp.prototype, "userId", void 0);
exports.Otp = Otp = tslib_1.__decorate([
    (0, mongoose_1.Schema)({ timestamps: true })
], Otp);
exports.OtpSchema = mongoose_1.SchemaFactory.createForClass(Otp);
// **Add this** right after creating the Schema:
exports.OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });


/***/ }),
/* 20 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(1);
tslib_1.__exportStar(__webpack_require__(21), exports);
tslib_1.__exportStar(__webpack_require__(22), exports);


/***/ }),
/* 21 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SharedSchemaModule = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
let SharedSchemaModule = class SharedSchemaModule {
};
exports.SharedSchemaModule = SharedSchemaModule;
exports.SharedSchemaModule = SharedSchemaModule = tslib_1.__decorate([
    (0, common_1.Module)({
        controllers: [],
        providers: [],
        exports: [],
    })
], SharedSchemaModule);


/***/ }),
/* 22 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserSchema = exports.User = void 0;
const tslib_1 = __webpack_require__(1);
const mongoose_1 = __webpack_require__(10);
const mongoose_2 = __webpack_require__(11);
const bcrypt = tslib_1.__importStar(__webpack_require__(12));
let User = class User extends mongoose_2.Document {
};
exports.User = User;
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], User.prototype, "firstName", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)(),
    tslib_1.__metadata("design:type", String)
], User.prototype, "lastName", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], User.prototype, "email", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], User.prototype, "password", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], User.prototype, "phone", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", Number)
], User.prototype, "age", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], User.prototype, "role", void 0);
exports.User = User = tslib_1.__decorate([
    (0, mongoose_1.Schema)()
], User);
exports.UserSchema = mongoose_1.SchemaFactory.createForClass(User);
exports.UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        const saltRounds = 10;
        this.password = await bcrypt.hash(this.password, saltRounds);
    }
    next();
});


/***/ }),
/* 23 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.authConfig = void 0;
const tslib_1 = __webpack_require__(1);
const dotenv = tslib_1.__importStar(__webpack_require__(24));
dotenv.config();
const authConfig = () => {
    return {
        port: 3000,
        twilio_sid: process.env.TWILIO_SID,
        twilio_token: process.env.TWILIO_TOKEN,
        twilio_from: "(320) 399-3295"
    };
};
exports.authConfig = authConfig;


/***/ }),
/* 24 */
/***/ ((module) => {

module.exports = require("dotenv");

/***/ }),
/* 25 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(1);
tslib_1.__exportStar(__webpack_require__(26), exports);
tslib_1.__exportStar(__webpack_require__(29), exports);


/***/ }),
/* 26 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.sharedConfig = sharedConfig;
const tslib_1 = __webpack_require__(1);
const dotenv = tslib_1.__importStar(__webpack_require__(24));
const fs = tslib_1.__importStar(__webpack_require__(27));
const path = tslib_1.__importStar(__webpack_require__(28));
dotenv.config();
function sharedConfig() {
    return {
        db_url: process.env.MONGODB_URI || '',
        privateKey: fs.readFileSync(path.join(process.cwd(), 'keys', 'rsa.key'), 'utf8'),
        publicKey: fs.readFileSync(path.join(process.cwd(), 'keys', 'rsa.key.pub'), 'utf8'),
        nodemailer_auth: {
            user: 'ss2202002@gmail.com',
            pass: 'ooutwtxyibkdghyw',
        },
    };
}


/***/ }),
/* 27 */
/***/ ((module) => {

module.exports = require("fs");

/***/ }),
/* 28 */
/***/ ((module) => {

module.exports = require("path");

/***/ }),
/* 29 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpExceptionFilter = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
let HttpExceptionFilter = class HttpExceptionFilter {
    // constructor(private logger: Logger) {}
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();
        const status = exception.getStatus();
        const info = exception.message;
        // this.logger.error(
        //     `${request.method} ${request.originalUrl} ${status} error: ${err}`
        // )
        response
            .status(status)
            .json({
            success: false,
            // timestamp: new Date().toISOString(),
            // path: request.url,
            info
        });
    }
};
exports.HttpExceptionFilter = HttpExceptionFilter;
exports.HttpExceptionFilter = HttpExceptionFilter = tslib_1.__decorate([
    (0, common_1.Catch)(common_1.HttpException)
], HttpExceptionFilter);


/***/ }),
/* 30 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateUserDTO = void 0;
const tslib_1 = __webpack_require__(1);
const class_validator_1 = __webpack_require__(31);
var UserRole;
(function (UserRole) {
    UserRole["RIDER"] = "RIDER";
    UserRole["DRIVER"] = "DRIVER";
    UserRole["ADMIN"] = "ADMIN";
})(UserRole || (UserRole = {}));
class CreateUserDTO {
}
exports.CreateUserDTO = CreateUserDTO;
tslib_1.__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MaxLength)(30),
    (0, class_validator_1.IsNotEmpty)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDTO.prototype, "firstName", void 0);
tslib_1.__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MaxLength)(30),
    (0, class_validator_1.IsNotEmpty)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDTO.prototype, "lastName", void 0);
tslib_1.__decorate([
    (0, class_validator_1.IsEmail)(),
    (0, class_validator_1.IsNotEmpty)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDTO.prototype, "email", void 0);
tslib_1.__decorate([
    (0, class_validator_1.IsStrongPassword)(),
    (0, class_validator_1.IsNotEmpty)(),
    tslib_1.__metadata("design:type", String)
], CreateUserDTO.prototype, "password", void 0);
tslib_1.__decorate([
    (0, class_validator_1.IsNumber)(),
    (0, class_validator_1.IsNotEmpty)(),
    tslib_1.__metadata("design:type", Number)
], CreateUserDTO.prototype, "phone", void 0);
tslib_1.__decorate([
    (0, class_validator_1.IsNumber)(),
    (0, class_validator_1.Min)(15),
    (0, class_validator_1.Max)(100),
    (0, class_validator_1.IsNotEmpty)(),
    tslib_1.__metadata("design:type", Number)
], CreateUserDTO.prototype, "age", void 0);
tslib_1.__decorate([
    (0, class_validator_1.IsEnum)(UserRole, { message: 'Role is empty or not a valid role' }),
    tslib_1.__metadata("design:type", String)
], CreateUserDTO.prototype, "role", void 0);


/***/ }),
/* 31 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 32 */
/***/ ((module) => {

module.exports = require("express");

/***/ }),
/* 33 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(1);
tslib_1.__exportStar(__webpack_require__(34), exports);
tslib_1.__exportStar(__webpack_require__(36), exports);


/***/ }),
/* 34 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtAuthGuard = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const passport_1 = __webpack_require__(35);
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)('jwt') {
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = tslib_1.__decorate([
    (0, common_1.Injectable)()
], JwtAuthGuard);


/***/ }),
/* 35 */
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),
/* 36 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtStrategy = void 0;
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const passport_1 = __webpack_require__(35);
const passport_jwt_1 = __webpack_require__(37);
const shared_config_1 = __webpack_require__(25);
const config = (0, shared_config_1.sharedConfig)();
const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['token'];
    }
    return token;
};
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    constructor() {
        super({
            jwtFromRequest: cookieExtractor,
            ignoreExpiration: false,
            secretOrKey: config.publicKey,
            algorithms: ['RS256']
        });
    }
    async validate(payload) {
        console.log("Validating", payload);
        return payload;
    }
};
exports.JwtStrategy = JwtStrategy;
exports.JwtStrategy = JwtStrategy = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [])
], JwtStrategy);


/***/ }),
/* 37 */
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ }),
/* 38 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.makeCookies = makeCookies;
function makeCookies(res, authToken, refreshToken) {
    res.cookie('token', authToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000,
    });
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
}


/***/ }),
/* 39 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RefreshTokenSchema = exports.RefreshToken = void 0;
const tslib_1 = __webpack_require__(1);
const mongoose_1 = __webpack_require__(10);
const mongoose_2 = __webpack_require__(11);
let RefreshToken = class RefreshToken extends mongoose_2.Document {
};
exports.RefreshToken = RefreshToken;
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.Schema.Types.ObjectId, ref: 'User', required: true }),
    tslib_1.__metadata("design:type", typeof (_b = typeof mongoose_2.Schema !== "undefined" && (_a = mongoose_2.Schema.Types) !== void 0 && _a.ObjectId) === "function" ? _b : Object)
], RefreshToken.prototype, "userId", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true, unique: true }),
    tslib_1.__metadata("design:type", String)
], RefreshToken.prototype, "token", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", typeof (_c = typeof Date !== "undefined" && Date) === "function" ? _c : Object)
], RefreshToken.prototype, "expires", void 0);
tslib_1.__decorate([
    (0, mongoose_1.Prop)({ required: true }),
    tslib_1.__metadata("design:type", String)
], RefreshToken.prototype, "tokenIndex", void 0);
exports.RefreshToken = RefreshToken = tslib_1.__decorate([
    (0, mongoose_1.Schema)()
], RefreshToken);
exports.RefreshTokenSchema = mongoose_1.SchemaFactory.createForClass(RefreshToken);
exports.RefreshTokenSchema.index({ expires: 1 }, { expireAfterSeconds: 0 });
exports.RefreshTokenSchema.index({ tokenIndex: 1 });


/***/ }),
/* 40 */
/***/ ((module) => {

module.exports = require("cookie-parser");

/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;

/**
 * This is not a production server yet!
 * This is only a minimal backend to get started.
 */
Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__(1);
const common_1 = __webpack_require__(2);
const core_1 = __webpack_require__(3);
const app_module_1 = __webpack_require__(4);
const shared_config_1 = __webpack_require__(25);
const cookie_parser_1 = tslib_1.__importDefault(__webpack_require__(40));
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.useGlobalFilters(new shared_config_1.HttpExceptionFilter());
    app.use((0, cookie_parser_1.default)());
    const globalPrefix = 'api';
    app.setGlobalPrefix(globalPrefix);
    const port = process.env.PORT || 3000;
    await app.listen(port);
    common_1.Logger.log(`🚀 Application is running on: http://localhost:${port}/${globalPrefix}`);
}
bootstrap();

})();

/******/ })()
;
//# sourceMappingURL=main.js.map