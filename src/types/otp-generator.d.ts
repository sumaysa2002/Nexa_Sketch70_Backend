declare module "otp-generator" {
  interface GenerateOptions {
    digits?: boolean;
    lowerCaseAlphabets?: boolean;
    upperCaseAlphabets?: boolean;
    specialChars?: boolean;
  }

  function generate(length: number, options?: GenerateOptions): string;

  export = {
    generate,
  };
}
