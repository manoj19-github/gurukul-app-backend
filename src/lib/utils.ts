import { registerDecorator } from 'class-validator';

export function IsValidProperty(pattern: RegExp) {
  return function (object, propertyName: string) {
    registerDecorator({
      name: 'IsValidProperty',
      target: object.constructor,
      propertyName: propertyName,
      constraints: [pattern],
      options: {
        message: '$property is not valid',
      },
      validator: {
        validate(value: any) {
          return pattern.test(value);
        },
      },
    });
  };
}
