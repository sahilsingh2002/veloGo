import {IsEmail, IsEnum, IsNotEmpty, IsNumber, IsString, IsStrongPassword, Max, MaxLength, Min} from 'class-validator'

enum UserRole {
    RIDER = 'RIDER',
    DRIVER = 'DRIVER',
    ADMIN = 'ADMIN',
  }

export class CreateUserDTO{
    @IsString()
    @MaxLength(30)
    @IsNotEmpty()
    readonly firstName:string;

    @IsString()
    @MaxLength(30)
    @IsNotEmpty()
    readonly lastName:string;

    @IsEmail()
    @IsNotEmpty()
    readonly email:string;

    @IsStrongPassword()
    @IsNotEmpty()
    readonly password:string;

    @IsNumber()
    @IsNotEmpty()
    readonly phone:number;

    @IsNumber()
    @Min(15)
    @Max(100)
    @IsNotEmpty()
    readonly age:number;

    //TODO: make better DTO, try to show the value and how it is incorrect in enum and other changes
    
    @IsEnum(UserRole, { message: 'Role is empty or not a valid role' })
    readonly role: UserRole;
}