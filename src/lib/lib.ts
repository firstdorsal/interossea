export const castableToNum = (input: string | undefined): boolean => {
    return input !== undefined && !isNaN(parseInt(input));
};
